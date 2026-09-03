# Система коллекторов SDA

## Краткий вывод

В репозитории SDA реализована система сбора статистики вызовов функций через динамические хуки. Общая идея действительно похожа на описанную: SDA загружается в адресное пространство процесса, для выбранных функций устанавливаются хуки, а callback получает аргументы до вызова и результат после вызова.

Однако фактическая реализация отличается от предположения о SQLite:

- SQLite используется как постоянное хранилище **метаданных** SDA: функций, сигнатур, типов, триггеров и фильтров.
- Сырые записи вызовов не вставляются в SQLite. Они сериализуются в бинарные файлы `buffer_tr<id>_<number>.data` в каталоге `buffers`.
- Входные данные (`before call`) сериализуются.
- Выходные данные (`after call`) в текущем исходном коде не сериализуются: `Collector::addAfterCallInfo` оставлен пустым.
- Поэтому на данный момент система является коллектором входных параметров с заделом под output, а не полностью реализованным input/output collector.

## 1. Как SDA попадает в процесс

### 1.1. Загрузка из MultiPlayer

Основной путь загрузки SDA выполняется из GUI MultiPlayer по нажатию `F3`:

1. Вызывается `LoadLibrary("FastLoader/SDA.dll")`.
2. Из DLL извлекается экспорт `GetSdaInterface`.
3. SDA получает окно и Direct3D swap chain.
4. Вызывается `SdaInterface::start()`.

Исходник: [`MultiPlayer/GUI/GUI.h#L155-L167`](../MultiPlayer/GUI/GUI.h#L155-L167), интерфейс DLL: [`Shared/SDA/SdaInterface.h#L24-L34`](../Shared/SDA/SdaInterface.h#L24-L34).

Есть также отдельная загрузка `SDA.dll` по `F5` через `LoadLibrary`, но в показанном коде результат не используется и интерфейс не запускается: [`MultiPlayer/main.cpp#L388-L393`](../MultiPlayer/main.cpp#L388-L393).

### 1.2. DLL entrypoint SDA

При `DLL_PROCESS_ATTACH` создается глобальный объект `Program`:

```text
DllMain
  -> new Program(hModule)
       -> определить каталог DLL
       -> создать ProjectManager
       -> CE::Hook::init()
```

Исходник: [`SDA/dll_main.cpp#L7-L25`](../SDA/dll_main.cpp#L7-L25), конструктор `Program`: [`SDA/Program.h#L6-L16`](../SDA/Program.h#L6-L16).

`CE::Hook::init()` вызывает `MH_Initialize()` MinHook. Обертка находится в [`SDA/Module/DynHook/DynHook.h#L14-L24`](../SDA/Module/DynHook/DynHook.h#L14-L24).

### 1.3. Важное различие между загрузкой и инжекцией

В текущем пути SDA загружается вызовом `LoadLibrary` из уже работающего MultiPlayer-процесса. Это не самостоятельный remote-process injector для произвольного target process.

В репозитории действительно есть классический инжектор, который:

- выделяет память в удаленном процессе через `VirtualAllocEx`;
- записывает путь DLL через `WriteProcessMemory`;
- запускает удаленный поток с `LoadLibraryW` через `CreateRemoteThread`.

Исходник: [`Injector/InjectorDLL2/main.cpp#L9-L60`](../Injector/InjectorDLL2/main.cpp#L9-L60). Отдельный `GTAV_Loader` перехватывает создание процесса и загружает DLL в новый target: [`GTAV_Loader/main.cpp#L77-L137`](../GTAV_Loader/main.cpp#L77-L137). Эти механизмы относятся к общей загрузке компонентов проекта; сам collector не занимается инжекцией.

## 2. Создание collector и каталогов

`Program` создает `ProjectManager`, но только его `start()` вызывает загрузку проектов: [`SDA/Program.h#L18-L21`](../SDA/Program.h#L18-L21). После открытия проекта создается `ProgramModule` в подкаталоге `Exe`: [`SDA/Project.h#L40-L50`](../SDA/Project.h#L40-L50).

`ProgramModule::initManagers()` создает `StatManager` вместе с менеджерами функций, типов, символов и триггеров: [`SDA/Module/Manager/ProgramModule.cpp#L55-L67`](../SDA/Module/Manager/ProgramModule.cpp#L55-L67).

В конструкторе `StatManager`:

1. Берется каталог проекта `Exe`.
2. Создается подкаталог `buffers`.
3. Создается `Stat::Function::Collector` с этим каталогом.

Исходник: [`SDA/Module/Manager/StatManager.cpp#L5-L12`](../SDA/Module/Manager/StatManager.cpp#L5-L12).

Структура владения:

```text
ProgramModule
  -> StatManager
       -> Collector
            -> BufferManager
                 -> TriggerBuffer per Trigger
                      -> BufferSaver per flushed buffer
```

Классы и поля описаны в [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.h#L58-L131`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.h#L58-L131).

## 3. Метаданные в SQLite

SQLite-база открывается как файл, имя которого передается в `ProgramModule::initDataBase`. При отсутствии файла выполняется встроенный SQL-ресурс создания общей схемы: [`SDA/Module/Manager/ProgramModule.cpp#L69-L93`](../SDA/Module/Manager/ProgramModule.cpp#L69-L93).

Схема содержит, в частности:

- `sda_functions` и `sda_func_ranges` для функций: [`SDA/Resources/SQL/create_general_db.sql#L126-L148`](../SDA/Resources/SQL/create_general_db.sql#L126-L148);
- `sda_triggers` для триггеров: [`SDA/Resources/SQL/create_general_db.sql#L182-L189`](../SDA/Resources/SQL/create_general_db.sql#L182-L189);
- `sda_func_trigger_filters` для фильтров триггеров: [`SDA/Resources/SQL/create_general_db.sql#L163-L168`](../SDA/Resources/SQL/create_general_db.sql#L163-L168);
- таблицы сигнатур, параметров и типов: [`SDA/Resources/SQL/create_general_db.sql#L94-L124`](../SDA/Resources/SQL/create_general_db.sql#L94-L124), [`SDA/Resources/SQL/create_general_db.sql#L191-L209`](../SDA/Resources/SQL/create_general_db.sql#L191-L209).

Загрузка функций и триггеров из SQLite выполняется менеджерами: [`SDA/Module/Manager/FunctionManager.cpp#L22-L24`](../SDA/Module/Manager/FunctionManager.cpp#L22-L24), [`SDA/Module/Manager/TriggerManager.cpp#L21-L24`](../SDA/Module/Manager/TriggerManager.cpp#L21-L24).

SQLite не является журналом отдельных runtime-вызовов. В исходниках нет `INSERT` в SQLite для каждого collected call; runtime-журнал идет в бинарные buffers.

При этом в репозитории присутствуют отдельные SQL-заготовки для call-level статистики: `sda_call_before`/`sda_call_args` и `sda_call_after`: [`SDA/Resources/SQL/collectors/create_callBefore_db.sql#L1-L15`](../SDA/Resources/SQL/collectors/create_callBefore_db.sql#L1-L15), [`SDA/Resources/SQL/collectors/create_callAfter_db.sql#L1-L8`](../SDA/Resources/SQL/collectors/create_callAfter_db.sql#L1-L8). Объединенная заготовка находится в [`SDA/Resources/SQL/create_generalStat_db.sql#L1-L25`](../SDA/Resources/SQL/create_generalStat_db.sql#L1-L25), но runtime collector эти таблицы не подключает и mapper-ов для них нет. Это проектировочный/неиспользуемый слой, а не фактическое хранилище текущих вызовов.

## 4. Создание и активация хуков

### 4.1. Хук функции

Для функции создается `FunctionTrigger::Hook`:

1. Адрес функции передается в `DynHook`.
2. Назначаются `callback_before` и `callback_after`.
3. Назначается `Method2<TriggerState>`, который хранит состояние текущего вызова.
4. Число аргументов берется из сигнатуры, но минимум устанавливается в 4.
5. В `userPtr` сохраняется описание функции.

Исходник: [`SDA/Module/Trigger/FunctionTriggerHook.cpp#L6-L12`](../SDA/Module/Trigger/FunctionTriggerHook.cpp#L6-L12).

Хук включается только когда у функции появляется первый активный trigger, и отключается после удаления последнего: [`SDA/Module/Trigger/FunctionTriggerHook.cpp#L26-L41`](../SDA/Module/Trigger/FunctionTriggerHook.cpp#L26-L41).

### 4.2. Что делает DynHook

`DynHook::enable()`:

1. Выделяет исполняемый буфер размером 500 байт.
2. Создает MinHook-хук с detour на этот динамический буфер.
3. Генерирует машинный код detour.
4. Включает MinHook.

Исходник: [`SDA/Module/DynHook/DynHook.h#L78-L101`](../SDA/Module/DynHook/DynHook.h#L78-L101), создание detour-буфера: [`SDA/Module/DynHook/DynHook.h#L125-L139`](../SDA/Module/DynHook/DynHook.h#L125-L139).

Сгенерированный код сохраняет первые четыре integer/register аргумента и первые четыре XMM-аргумента, создает thread-local состояние вызова, вызывает before callback, при разрешении передает управление оригинальному trampoline, затем сохраняет return values и вызывает after callback: [`SDA/Module/DynHook/DynHook.h#L344-L507`](../SDA/Module/DynHook/DynHook.h#L344-L507).

Доступ к значениям реализован через `getArgumentValue`, `getXmmArgumentValue`, `getReturnValue` и `getReturnAddress`: [`SDA/Module/DynHook/DynHook.h#L510-L555`](../SDA/Module/DynHook/DynHook.h#L510-L555).

### 4.3. Callback цепочка

Before callback проходит по всем активным trigger функции и вызывает `actionBefore`: [`SDA/Module/Trigger/FunctionTrigger.cpp#L122-L128`](../SDA/Module/Trigger/FunctionTrigger.cpp#L122-L128).

After callback аналогично вызывает `actionAfter`: [`SDA/Module/Trigger/FunctionTrigger.cpp#L162-L167`](../SDA/Module/Trigger/FunctionTrigger.cpp#L162-L167).

Trigger активируется через `start()`, который добавляет его во все function hooks, и останавливается через `stop()`: [`SDA/Module/Trigger/FunctionTrigger.cpp#L81-L89`](../SDA/Module/Trigger/FunctionTrigger.cpp#L81-L89), [`SDA/Module/Trigger/FunctionTrigger.cpp#L109-L119`](../SDA/Module/Trigger/FunctionTrigger.cpp#L109-L119).

## 5. Сбор input до вызова

`Trigger::actionBefore` сначала применяет before-фильтр. Если он сработал, в thread-local `TriggerState` выставляется `m_beforeFilter`. Затем при включенном collector выполняется `addBeforeCallInfo`: [`SDA/Module/Trigger/FunctionTrigger.cpp#L22-L39`](../SDA/Module/Trigger/FunctionTrigger.cpp#L22-L39).

Сбор разрешается в двух случаях:

- before-фильтр совпал;
- установлен `m_sendStatAnyway`.

`Collector::addBeforeCallInfo` создает `Record::BeforeCallInfo::Writer` и передает его в `BufferManager`: [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L114-L118`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L114-L118).

### Формат записи

Каждая запись начинается с `Record::Header`:

```text
BYTE     type              // BeforeCallInfo или AfterCallInfo
uint64   uid               // идентификатор конкретного вызова
int      triggerId
int      funcDefId
```

Определение: [`SDA/Module/Statistic/Function/Collector/Record/CallInfoWriter.h#L12-L24`](../SDA/Module/Statistic/Function/Collector/Record/CallInfoWriter.h#L12-L24). Заполнение header: [`SDA/Module/Statistic/Function/Collector/Record/CallInfoWriter.cpp#L6-L13`](../SDA/Module/Statistic/Function/Collector/Record/CallInfoWriter.cpp#L6-L13).

Для before-записи далее идет `ArgHeader`:

```text
uint64   m_argExtraBits   // какие аргументы имеют дополнительный payload
BYTE     m_argCount
```

Затем по каждому аргументу записываются:

- raw register/stack значение `uint64`;
- XMM-значение для аргументов 1–4;
- при наличии extra payload: короткая информация о типе, размер `USHORT` и копия данных.

Исходник writer: [`SDA/Module/Statistic/Function/Collector/Record/BeforeCallInfo.cpp#L47-L80`](../SDA/Module/Statistic/Function/Collector/Record/BeforeCallInfo.cpp#L47-L80), структуры и reader: [`SDA/Module/Statistic/Function/Collector/Record/BeforeCallInfo.h#L6-L55`](../SDA/Module/Statistic/Function/Collector/Record/BeforeCallInfo.h#L6-L55).

Для указательных/строковых типов `writeTypeValue` разыменовывает значение согласно описанию типа, сохраняет до 100 байт строки либо размер объекта типа, и записывает payload: [`SDA/Module/Statistic/Function/Collector/Record/CallInfoWriter.cpp#L15-L45`](../SDA/Module/Statistic/Function/Collector/Record/CallInfoWriter.cpp#L15-L45).

## 6. Буферизация и запись на диск

`BufferManager` хранит отдельный `TriggerBuffer` для каждого trigger. Доступ защищен одним `std::mutex`: [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L24-L31`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L24-L31).

`TriggerBuffer` по умолчанию создает буфер размером 1 MiB. При переполнении:

1. При необходимости текущий размер удваивается.
2. Текущий buffer передается на сохранение.
3. Создается новый buffer.
4. Запись повторяется.

Исходник: [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L61-L75`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L61-L75), создание буфера: [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L91-L99`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L91-L99).

Имя файла формируется как `buffer_tr<TriggerId>_<sequence>.data`: [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L86-L89`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L86-L89).

Физическая запись выполняется в detached thread через `std::ofstream` в binary mode: [`SDA/Module/Statistic/Function/Collector/CollectingBufferSaver.cpp#L9-L23`](../SDA/Module/Statistic/Function/Collector/CollectingBufferSaver.cpp#L9-L23).

При сохранении менеджер передает текущий буфер, ожидает завершения saver-потоков с polling через `Sleep(100)`, удаляет `TriggerBuffer`: [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L33-L42`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L33-L42).

## 7. Сбор output после вызова

Логика trigger предусмотрена: `actionAfter` запускает after-фильтры и при совпадении должен вызвать `Collector::addAfterCallInfo`: [`SDA/Module/Trigger/FunctionTrigger.cpp#L42-L58`](../SDA/Module/Trigger/FunctionTrigger.cpp#L42-L58).

Но сам метод пуст:

```cpp
void Collector::addAfterCallInfo(...)
{
}
```

Исходник: [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L120-L123`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L120-L123).

Следствия:

- return value и return XMM value технически доступны через `DynHook`;
- return address также доступен;
- after callback вызывается;
- но ни один из этих output-параметров сейчас не попадает в buffer-файл;
- `Record::Type::AfterCallInfo` существует как задел формата, но writer/reader для after-записи не реализованы.

## 8. Чтение и анализ собранных данных

`BufferLoader::loadAllBuffers()` перечисляет содержимое каталога `buffers`. `getBuffer()` пропускает файлы без подстроки `buffer_tr`, читает `Buffer::Header`, выделяет буфер нужного размера и загружает бинарные данные: [`SDA/Module/Statistic/Function/Analysis/FunctionStatAnalyser.cpp#L86-L117`](../SDA/Module/Statistic/Function/Analysis/FunctionStatAnalyser.cpp#L86-L117).

Анализатор создает отдельный `BufferAnalyser` для каждого загруженного buffer и перебирает записи. Для каждой записи читается общий `Record::Header`, после чего поток передается `IAnalysisProvider`: [`SDA/Module/Statistic/Function/Analysis/FunctionStatAnalyser.cpp#L19-L32`](../SDA/Module/Statistic/Function/Analysis/FunctionStatAnalyser.cpp#L19-L32), [`SDA/Module/Statistic/Function/Analysis/FunctionStatAnalyser.cpp#L72-L80`](../SDA/Module/Statistic/Function/Analysis/FunctionStatAnalyser.cpp#L72-L80).

GUI-окно анализа именно загружает buffers, а не делает SQL-запросы за runtime-вызовами: [`SDA/GUI_old/Windows/StatisticAnalyser.cpp#L34-L39`](../SDA/GUI_old/Windows/StatisticAnalyser.cpp#L34-L39).

Тест подтверждает ожидаемый pipeline: сначала вызывается `BufferManager::save()`, затем `BufferLoader` читает buffers, а `StringSearchProvider` находит строки в записях: [`SDA/tests/CommonTest.cpp#L440-L460`](../SDA/tests/CommonTest.cpp#L440-L460).

## 9. Фильтры, table log и collector

Collector является одним из трех действий trigger:

1. фильтрация вызова;
2. запись структурированной строки в `TableLog`;
3. запись бинарной статистики в `Collector`.

`TableLog` отдельно сохраняет аргументы и return value в оперативную таблицу до/после вызова: [`SDA/Module/Trigger/FunctionTrigger.cpp#L30-L36`](../SDA/Module/Trigger/FunctionTrigger.cpp#L30-L36), [`SDA/Module/Trigger/FunctionTrigger.cpp#L49-L55`](../SDA/Module/Trigger/FunctionTrigger.cpp#L49-L55). Это не SQLite collector storage и не тот же формат, что бинарные buffers.

## 10. Ограничения и риски текущей реализации

- **Output не записывается.** `addAfterCallInfo` пуст, поэтому заявленная пара input/output фактически не реализована.
- **Данные не в SQLite.** SQLite содержит описание и конфигурацию, а raw calls находятся в `.data` файлах.
- **Автоматический runtime-поток не доведен до конца.** `DllMain` создает `Program`, но не вызывает `Program::start()`: [`SDA/dll_main.cpp#L12-L18`](../SDA/dll_main.cpp#L12-L18), [`SDA/Program.h#L18-L21`](../SDA/Program.h#L18-L21). Более того, в `Project::load()` вызовы `initDataBase`, `initManagers` и `load` находятся в закомментированном блоке: [`SDA/Project.h#L52-L80`](../SDA/Project.h#L52-L80). Поэтому приведенная выше цепочка является реализованным каркасом, но не гарантированным путем автоматического запуска из одной только DLL-загрузки.
- **Есть риск рассинхронизации проекта сборки и DLL entrypoint.** В `SDA.vcxproj` тип конфигурации DLL и выход в `FastLoader` присутствуют: [`SDA/SDA.vcxproj#L34-L62`](../SDA/SDA.vcxproj#L34-L62), [`SDA/SDA.vcxproj#L95-L118`](../SDA/SDA.vcxproj#L95-L118), однако в списке исходников указан `main.cpp`, а `dll_main.cpp` там не найден: [`SDA/SDA.vcxproj#L240-L243`](../SDA/SDA.vcxproj#L240-L243). `main.cpp` содержит `wWinMain` GUI-приложения: [`SDA/main.cpp#L18-L22`](../SDA/main.cpp#L18-L22). Это следует проверить в конфигурации сборки отдельно.
- **Имена DLL в разных путях не единообразны.** `GTAV_Loader` ищет `FastLoader\MultiPlayer.dll`: [`GTAV_Loader/main.cpp#L99-L121`](../GTAV_Loader/main.cpp#L99-L121), тогда как интерфейс GUI загружает `FastLoader/SDA.dll`: [`MultiPlayer/GUI/GUI.h#L155-L160`](../MultiPlayer/GUI/GUI.h#L155-L160). Следовательно, loader и ручной GUI-путь могут относиться к разным артефактам сборки.
- **Некорректная семантика результата инициализации MinHook.** `CE::Hook::init()` возвращает `MH_Initialize() != MH_OK`, то есть `true` при ошибке и `false` при успехе: [`SDA/Module/DynHook/DynHook.h#L18-L24`](../SDA/Module/DynHook/DynHook.h#L18-L24).
- **Синхронизация грубая.** `BufferManager::write` удерживает один mutex во время полной сериализации записи: [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L24-L31`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L24-L31).
- **Detached saver threads.** Потоки записи detach-ятся; корректность завершения контролируется флагом `m_isWorking`, а время жизни самого `Buffer` зависит от этого ручного протокола: [`SDA/Module/Statistic/Function/Collector/CollectingBufferSaver.cpp#L9-L23`](../SDA/Module/Statistic/Function/Collector/CollectingBufferSaver.cpp#L9-L23).
- **Есть polling вместо condition variable.** При flush используется `Sleep(100)`, что добавляет задержку и не дает строгого события завершения: [`SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L33-L42`](../SDA/Module/Statistic/Function/Collector/FunctionStatCollector.cpp#L33-L42).
- **Ручной формат не версионируется.** В binary record header нет version/size поля записи. Изменение структуры writer требует синхронного обновления reader и анализаторов.
- **Размер записи технически сохраняется, но границы недостаточно защищены.** `StreamRecord` пишет длину перед payload, а `BufferIterator` проверяет ее относительно content offset, однако проверка прямо помечена TODO: [`SDA/Utils/BufferStreamRecorder.cpp#L9-L11`](../SDA/Utils/BufferStreamRecorder.cpp#L9-L11), механизм длины записи: [`SDA/Utils/BufferStreamRecorder.cpp#L28-L46`](../SDA/Utils/BufferStreamRecorder.cpp#L28-L46).
- **Ограниченная ABI-модель хуков.** Генератор явно работает с первыми четырьмя register/XMM аргументами, а остальные читает через стековую адресацию: [`SDA/Module/DynHook/DynHook.h#L389-L414`](../SDA/Module/DynHook/DynHook.h#L389-L414), [`SDA/Module/DynHook/DynHook.h#L514-L532`](../SDA/Module/DynHook/DynHook.h#L514-L532).
- **Небезопасное разыменование аргументов.** `writeTypeValue` читает память по указателю из target process при сериализации extra payload; полноценной проверки доступности указателя в collector нет: [`SDA/Module/Statistic/Function/Collector/Record/CallInfoWriter.cpp#L19-L44`](../SDA/Module/Statistic/Function/Collector/Record/CallInfoWriter.cpp#L19-L44).
- **Активные trigger-ы меняются без реализованной синхронизации.** В `addActiveTrigger`/`removeActiveTrigger` оставлены комментарии `//mutex`, но фактической блокировки списка нет: [`SDA/Module/Trigger/FunctionTriggerHook.cpp#L26-L40`](../SDA/Module/Trigger/FunctionTriggerHook.cpp#L26-L40).
- **Возможны проблемы жизненного цикла.** В `DllMain` создается тяжелый объект `Program`, который инициализирует менеджеры/MinHook-подсистему. Для Windows loader lock это потенциально опаснее, чем отложенная инициализация из отдельного потока: [`SDA/dll_main.cpp#L12-L18`](../SDA/dll_main.cpp#L12-L18).
- **После сбоя записи ошибок не видно в collector API.** `BufferSaver` просто закрывает поток после проверки `is_open`, без сообщения об ошибке: [`SDA/Module/Statistic/Function/Collector/CollectingBufferSaver.cpp#L15-L22`](../SDA/Module/Statistic/Function/Collector/CollectingBufferSaver.cpp#L15-L22).

## 11. Итоговая схема

```text
MultiPlayer
  -> LoadLibrary("FastLoader/SDA.dll")
  -> GetSdaInterface()->start()
  -> SDA::Program / Project / ProgramModule
  -> StatManager
  -> Collector -> BufferManager -> buffers/

Function + Trigger
  -> FunctionTrigger::Hook
  -> DynHook + MinHook + generated machine-code detour
  -> callback_before
  -> filters
  -> BeforeCallInfo::Writer
  -> BufferManager::write
  -> buffer_tr*.data

Original function
  -> callback_after
  -> filters / TableLog
  -> addAfterCallInfo (currently empty)

SQLite
  -> functions, signatures, types, triggers, filters, project metadata
  -> не содержит raw runtime call records
```

Таким образом, корректное описание текущей системы: **SDA загружается в процесс, создает MinHook/DynHook для функций, активные triggers собирают before-call аргументы и складывают бинарные записи в per-trigger buffers; SQLite хранит метаданные, а after-call collector пока не реализован.**
