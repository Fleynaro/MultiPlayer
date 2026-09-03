# MultiPlayer: устройство проекта

## 1. Краткий вывод

`MultiPlayer` в текущем состоянии является не самостоятельным сетевым сервером и не готовым клиентом GTA Online, а внедряемой в процесс GTA V нативной DLL. Она:

- загружается в `GTA5.exe` через цепочку `InjectorDLL2 -> GTAV_loader -> MultiPlayer.dll`;
- находит функции и глобальные структуры игры по сигнатурам машинного кода;
- ставит MinHook-хуки на игровой цикл, выполнение скриптов, ввод, Direct3D 11 и отдельные игровые подсистемы;
- публикует единый поток событий для своих модулей;
- предоставляет C++ SDK для native-функций GTA, педов, транспорта, оружия, костей, анимаций и пулов;
- содержит GUI на ImGui и задел для Lua/V8-скриптов;
- отключает часть одиночной игровой логики и оставляет выбранные игровые скрипты активными.

В каталоге `MultiPlayer` нет собственной сетевой подсистемы: не найдено TCP/UDP-соединений, сетевого протокола, списка удаленных игроков, репликации состояния, авторизации или серверного кода. Слово `network` встречается главным образом в названиях встроенных GTA native-функций и в именах штатных игровых скриптов. Поэтому точнее описывать проект как **инструмент модификации и расширения локально запущенной GTA V**, подготовленный для будущего мультиплеерного слоя.

## 2. Состав репозитория

Главные части решения:

| Каталог | Назначение |
|---|---|
| [`MultiPlayer/`](../MultiPlayer/) | Основная DLL: хуки, игровой SDK, native-функции, GUI, языки скриптов. |
| [`Injector/InjectorDLL2/`](../Injector/InjectorDLL2/) | EXE-инжектор: запускает лаунчер в suspended-состоянии и внедряет loader DLL. |
| [`GTAV_Loader/`](../GTAV_Loader/) | DLL-loader: перехватывает запуск `GTA5.exe` и внедряет `MultiPlayer.dll`. |
| [`Shared/`](../Shared/) | Небольшой общий проект и интерфейс SDA. |
| [`GUI_Lib/`](../GUI_Lib/) | Отдельная библиотека GUI и редактора кода, используемая исторически/параллельно с GUI внутри `MultiPlayer`. |
| [`SDA/`](../SDA/) | Инструменты анализа/декомпиляции и отдельная DLL, которую можно догрузить из GUI. Это не сетевой слой MultiPlayer. |
| `Test/`, `TestCodeToDecompile/` | Экспериментальные проекты. |

Основной проект собирается как `DynamicLibrary`, только под `x64`; конфигурации описаны в [`MultiPlayer.vcxproj`](../MultiPlayer/MultiPlayer.vcxproj#L25-L45). Используются C++17, Windows SDK, Direct3D 11, MinHook, Lua, V8/Chromium, ImGui, GLM и JSON. Выход DLL направляется в каталог `$(GTA5_ROOT)\FastLoader` ([проект](../MultiPlayer/MultiPlayer.vcxproj#L61-L77)).

## 3. Как запускается цепочка

### 3.1. Инжектор

[`InjectorDLL2/main.cpp`](../Injector/InjectorDLL2/main.cpp#L107-L146) является точкой входа небольшого Windows-приложения:

1. Принудительно задает командную строку `GTAVLauncher.exe`.
2. Включает debug privilege через `AdjustTokenPrivileges` ([строки 81-105](../Injector/InjectorDLL2/main.cpp#L81-L105)).
3. Запускает лаунчер с `CREATE_SUSPENDED`.
4. Ищет `FastLoader\GTAV_loader.dll`.
5. Внедряет loader в процесс через `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` и `LoadLibraryW` ([строки 9-60](../Injector/InjectorDLL2/main.cpp#L9-L60)).
6. Возобновляет поток лаунчера.

Это классический DLL-инжект через удаленный поток. В коде есть слабые места: часть дескрипторов и выделенной памяти не освобождается при ранних ошибках, путь жестко задан относительно текущего каталога, а используется `PROCESS_ALL_ACCESS`.

### 3.2. Loader

[`GTAV_Loader/main.cpp`](../GTAV_Loader/main.cpp#L77-L137) перехватывает `CreateProcessA` с помощью MinHook. Proxy добавляет к флагам `CREATE_SUSPENDED`, а затем:

- проверяет, что запускается именно `GTA5.exe`;
- ищет `FastLoader\*.dll`, но фактически пропускает только файл `MultiPlayer.dll` ([строки 99-120](../GTAV_Loader/main.cpp#L99-L120));
- внедряет его в процесс GTA;
- отключает собственный хук `CreateProcessA`;
- возобновляет поток GTA.

Инициализация loader выполняется в `DllMain`: MinHook создается, устанавливается хук на `CreateProcessA`, а пользователю показывается диагностическое окно ([строки 140-172](../GTAV_Loader/main.cpp#L140-L172)).

### 3.3. Вход в MultiPlayer.dll

Точка входа основной DLL находится в [`MultiPlayer/main.cpp`](../MultiPlayer/main.cpp#L400-L429). При `DLL_PROCESS_ATTACH` код:

1. Ждет 2 секунды.
2. Регистрирует `Update1` в источнике событий игрового script engine.
3. Регистрирует `InputHandler2` в источнике событий клавиатуры.
4. Создает `GameAppInfo`, сохраняя HMODULE текущей DLL.
5. Создает `Core`, который выполняет основную инициализацию.
6. Пишет `MultiPlayer started!` в отладочный вывод.

Задержка и работа в `DllMain` потенциально опасны: тяжелая инициализация выполняется в контексте загрузчика DLL. Сам loader частично компенсирует это тем, что встраивает DLL до возобновления игрового потока, но архитектурно надежнее запускать тяжелый код из отдельного потока после минимального `DllMain`.

`GameAppInfo` хранит handle DLL и дает пути к директории DLL и к директории игры ([`GameAppInfo.h`](../MultiPlayer/Game/GameAppInfo.h#L9-L34)). Через это, например, строится путь `MultiPlayer.dll\scripts`.

## 4. Порядок инициализации Core

Конструктор [`Core`](../MultiPlayer/Core/Core.h#L22-L40) задает фактический порядок запуска:

1. `MH_Initialize()` — запуск MinHook.
2. `defineGameVersion()` — выбирается адаптер версии `GameVersionHook_141`.
3. `installGameHooks()` — все подсистемы добавляют свои сигнатуры поиска.
4. `completeGameHooks()` — загружается кэш offsets, сканируется GTA-модуль, хуки активируются обработчиками.
5. `disableGameScripts()` — выключается большинство штатных игровых скриптов.
6. `GUI_init()` — добавляются обработчик GUI-ввода и игровой GUI-контекст.
7. `UserKeyboardList::init()`.
8. `GameScriptEngine::init()` — регистрируются группы native-функций.
9. `initScriptLangs()` — строятся экспорты SDK и инициализируются JavaScript/Lua.

Ошибка поиска любого обязательного паттерна превращается в `GameHookException`; `completeGameHooks()` показывает MessageBox и завершает процесс через `ExitProcess(2)` ([`Core.h`](../MultiPlayer/Core/Core.h#L86-L106)). Это делает несовместимость с другой версией GTA явной, но не дает безопасного частичного запуска.

## 5. Система хуков и сигнатур

### 5.1. Общий интерфейс

[`IGameHook`](../MultiPlayer/Game/IGameHook.h#L15-L28) задает два действия: `Install()` и `Remove()`. [`IGameHooked`](../MultiPlayer/Game/IGameHooked.h#L7-L21) перед установкой передает хуку владельца через `Init()`.

Версионный фасад [`GameVersionHook_141`](../MultiPlayer/Game/GameVersionHook.h#L20-L105) создает генераторы хуков для:

- игрового script engine;
- пулов объектов;
- преобразования адреса объекта;
- игрового update;
- выхода из игры;
- окна и ввода;
- Direct3D 11;
- загрузки сохранения;
- курсора;
- удаления одиночных элементов;
- регистрации native-функций.

Пока есть только адаптер `V141`, а native hash adapter явно переключается на `V141` ([`GameVersionHook.h`](../MultiPlayer/Game/GameVersionHook.h#L102-L105)). Это важная граница совместимости: смещение полей и машинные сигнатуры рассчитаны на конкретную версию игры.

### 5.2. Поиск адресов

[`GameHookList`](../MultiPlayer/Game/GameHookList.h#L10-L38) собирает объекты `FoundPattern`. Каждый модуль при `Install()` добавляет одну или несколько сигнатур байтов. После этого список:

1. читает `offsets.json` из директории DLL;
2. пытается проверить сохраненные RVA;
3. сканирует основной модуль GTA для не найденных адресов;
4. сохраняет найденные RVA обратно;
5. очищает список паттернов.

Реализация сканирования находится в [`Pattern.h`](../MultiPlayer/Utility/Pattern.h#L96-L235). Поддерживаются wildcard-байты `?`, специальная отметка `*` для начала адреса, обычный и SSE4.2-путь поиска. `Memory::Handle::rip()` преобразует RIP-relative инструкцию в реальный адрес, а `toRVA/fromRVA` позволяют хранить адреса относительно базы модуля ([`MemoryHandle.h`](../MultiPlayer/Utility/MemoryHandle.h#L112-L155)).

### 5.3. MinHook-обертка

[`Memory::FunctionHook`](../MultiPlayer/Utility/MemoryHandle.h#L527-L652) хранит исходную функцию, proxy-функцию и оригинальный trampoline. Методы `hook`, `enable`, `disable`, `executeOrigFunc` позволяют либо полностью заменить функцию, либо выполнить свою логику и передать управление оригиналу. Метод `hookWithNothing()` используется для подавления функции, возвращая `NULL` для non-void результата.

## 6. Игровой цикл и шина событий

### 6.1. Типы событий

[`GameEvent.h`](../MultiPlayer/Game/GameEvent.h#L5-L18) объявляет события:

- `GAME_INIT` и `GAME_UPDATE`;
- `GAME_INPUT`;
- `GAME_D3D_PRESENT` и `GAME_D3D_INIT`;
- `GAME_SCRIPT_EXECUTE`;
- `CONTEXT_UPDATER`.

Шина `IGameEventGenPublisher` хранит общий список обработчиков, сортирует их по приоритету и может остановить дальнейшую обработку, если обработчик выставил `doContinue = false` ([`GameEvent.h`](../MultiPlayer/Game/GameEvent.h#L210-L244)). Это центральный механизм связи между хуками и расширениями.

### 6.2. Update

`GameUpdateHook_Gen` находит функцию главного обновления по паттерну и ставит proxy ([`GameUpdate.h`](../MultiPlayer/Game/GameUpdate.h#L105-L130)). `MainUpdateHook` при первом вызове посылает `GAME_INIT`, затем на каждом кадре `GAME_UPDATE`, считает интервал кадра и вызывает оригинальную функцию ([`GameUpdate.h`](../MultiPlayer/Game/GameUpdate.h#L57-L101)).

Базовый script context получает кадры через `GAME_SCRIPT_EXECUTE`, а не напрямую из `OnUpdate`. `IGameScriptContext::Main()` лениво создает fiber, выполняет его и передает управление обратно главному fiber ([`GameScriptEngine.h`](../MultiPlayer/Game/ScriptEngine/GameScriptEngine.h#L71-L139)).

### 6.3. Отложенные события и fibers

`GameEventProxyHandler` не вызывает обработчик сразу: он складывает сообщение в `GameEventProxyMessageAgregator`. Позже `sendMessages()` вызывает исходный callback ([`GameEvent.h`](../MultiPlayer/Game/GameEvent.h#L116-L205)). Это нужно, чтобы обработчики, связанные с игровым скриптом, выполнялись в подходящем fiber-контексте.

`sleep(ms)` записывает время пробуждения и возвращает управление главному fiber; `yield()` является сокращением для `sleep(0)` ([`GameScriptEngine.h`](../MultiPlayer/Game/ScriptEngine/GameScriptEngine.h#L189-L205)). Контекст хранит до 30 сообщений консольного лога ([строки 207-227](../MultiPlayer/Game/ScriptEngine/GameScriptEngine.h#L207-L227)).

## 7. Ввод и курсор

`GameInputHook_Gen` в отдельном потоке ищет окно `grcWindow` и заменяет его `WndProc` ([`GameInput.h`](../MultiPlayer/Game/GameInput.h#L179-L209)). Новый `WndProc` превращает каждое Windows-сообщение мыши/клавиатуры в `GameEventInputMessage`, отправляет его обработчикам и при необходимости вызывает оригинальный оконный callback ([`GameInput.h`](../MultiPlayer/Game/GameInput.h#L144-L175)). Поддерживаются key up/down, кнопки мыши, движение, колесо и модификаторы Shift/Ctrl/Alt.

В основной DLL `InputHandler2` реализует тестовые горячие клавиши ([`main.cpp`](../MultiPlayer/main.cpp#L361-L395)):

- `F1` показывает/скрывает курсор;
- `F2` переключает режим невозврата курсора;
- `F3` завершает игру;
- `F5` догружает `SDA.dll`.

GUI-обработчик имеет высокий приоритет и, когда окна GUI показаны, передает сообщения ImGui и останавливает их дальнейшее прохождение в игру ([`GUI.h`](../MultiPlayer/GUI/GUI.h#L135-L146)).

## 8. Direct3D 11 и отрисовка GUI

[`Direct3D11`](../MultiPlayer/Game/DirectX/Direct3D11.h#L70-L124) перехватывает `IDXGISwapChain::Present`. При первом вызове получает device/context, затем публикует `GAME_D3D_INIT` и каждый кадр `GAME_D3D_PRESENT`.

Внутренний `Draw` создает ImGui context, подключает Win32 и DX11 backends, регистрирует шрифты и тему ([`GUI.h`](../MultiPlayer/GUI/GUI.h#L98-L110)). На каждом `Present` он:

1. начинает новые ImGui-кадры;
2. рисует зарегистрированные окна;
3. рисует popup-контекст;
4. обрабатывает UI-события;
5. вызывает `ImGui::Render()` и `ImGui_ImplDX11_RenderDrawData()`;
6. при наличии вызывает рендер SDA.

Первое открытие UI происходит по `F4`: регистрируется `Draw`, добавляются окна, показывается курсор и затем управление игроком блокируется при открытом интерфейсе ([`GUI.h`](../MultiPlayer/GUI/GUI.h#L170-L185)). Сейчас по умолчанию регистрируется `ContextManager` ([`GUI.h`](../MultiPlayer/GUI/GUI.h#L51-L54)).

## 9. Отключение одиночной логики

### 9.1. Список игровых скриптов

[`GameScripts`](../MultiPlayer/Game/GameScripts.h#L14-L85) создает большой статический список имен штатных GTA-скриптов. Для каждого хранится имя, `std::hash`, счетчик вызовов, флаг enabled и флаг terminated.

Хук `executeScriptHook` читает имя текущего скрипта из структуры по смещению `0xD0`, увеличивает счетчик и возвращает `0`, если скрипт отключен; иначе вызывает оригинал ([`GameScripts.h`](../MultiPlayer/Game/GameScripts.h#L89-L180)).

`Core::disableGameScripts()` сначала выключает весь список, затем включает небольшой набор: `building_controller`, `initial`, `main`, `standard_global_init`, `pausemenu_map`, `standard_global_reg`, `startup`, `startup_positioning`, `vehicle_gen_controller`, `main_persistent` ([`Core.h`](../MultiPlayer/Core/Core.h#L109-L123)). После запуска `Update1::OnInit()` вызывает `terminateDisabledScripts()`, что отправляет отключенным скриптам native `TERMINATE_ALL_SCRIPTS_WITH_THIS_NAME` ([`main.cpp`](../MultiPlayer/main.cpp#L120-L137), [`GameScripts.h`](../MultiPlayer/Game/GameScripts.h#L121-L128)).

### 9.2. Удаление одиночных сущностей

[`GameRemoveSingleElements`](../MultiPlayer/Game/MultiPlayer/GameRemoveSingleElements.h#L18-L64) подавляет ряд процедур одиночной игры: спавн некоторых педов и машин, пожарных, далекие fake vehicles, special skill, wanted/police update. Часть хуков заменена пустой функцией, а часть фильтрует вызов.

Особенно важны два фильтра:

- `SpawnPeds2_hook` возвращает `1` для типа/режима, соответствующего выбранному одиночному спавну;
- `SpawnVehicle2_hook` блокирует вызов, если текущий скрипт — `vehicle_gen_controller` ([строки 45-63](../MultiPlayer/Game/MultiPlayer/GameRemoveSingleElements.h#L45-L63)).

Отключение выполняется при первом `GAME_INIT` через вызов `DisableSpawnVehicle()` ([строки 24-29](../MultiPlayer/Game/MultiPlayer/GameRemoveSingleElements.h#L24-L29)). Название подсистемы указывает на подготовку игрового мира под multiplayer-сценарий, но полноценная репликация удаленных игроков здесь не реализована.

### 9.3. Сохранение

`GameStartLoad` перехватывает загрузку сохранения и подставляет бинарный ресурс `SAVE` из ресурсов DLL. Данные можно читать/писать во внешний файл, загружать из ресурса и подменять структуру `CGameSaveInfo` ([`GameStartLoad.h`](../MultiPlayer/Game/MultiPlayer/GameStartLoad.h#L17-L145)). При старте загрузки вызываются `LoadGeneral`, `LoadSave`, `LoadEnd`, а часть категорий статистики блокируется ([строки 277-349](../MultiPlayer/Game/MultiPlayer/GameStartLoad.h#L277-L349)).

## 10. Native-функции GTA

### 10.1. Регистрация

`GameScriptEngine::init()` создает карту групп native-функций: `PLAYER`, `ENTITY`, `PED`, `VEHICLE`, `OBJECT`, `STATS`, `WEAPON`, `TIME`, `WORLDPROBE`, `WATER`, `FIRE`, `AI`, `GAMEPLAY`, `AUDIO`, `CAM`, `UI`, `GRAPHICS`, `STREAMING`, `SYSTEM` ([`GameScriptEngine.h`](../MultiPlayer/Game/ScriptEngine/GameScriptEngine.h#L264-L301)).

Затем `initNatives()` связывает эти описания с hash-таблицей игры ([строки 239-262](../MultiPlayer/Game/ScriptEngine/GameScriptEngine.h#L239-L262)). `GameScriptEngineHook_Gen` перехватывает регистрацию native и сохраняет пару `hash -> handler`, а также ставит хук на `Sleep`, чтобы генерировать событие выполнения скрипта ([строки 346-364](../MultiPlayer/Game/ScriptEngine/GameScriptEngine.h#L346-L364)).

Версия hash-таблицы выбирается как `V141`, поэтому native-обертки привязаны к соответствующей версии GTA.

### 10.2. Вызов

[`SDK::Call`](../MultiPlayer/SDK/NativeCaller.h#L43-L54) выводит сигнатуру native из типа `T`, приводит объект к `IGameNative` и вызывает `execute`. На этом построены более удобные C++-объекты SDK.

Например, [`SDK::CREATE`](../MultiPlayer/SDK/Builder.h#L12-L60) загружает модель и вызывает `PED::CREATE_PED`, а `MP_Player` выбирает тип `PED_TYPE_NETWORK_PLAYER`. `VEHICLE()` вызывает `VEHICLE::CREATE_VEHICLE` с сетевыми флагами `TRUE, TRUE` ([`Builder.h`](../MultiPlayer/SDK/Builder.h#L125-L152)). Это означает использование параметров штатной native-функции, а не наличие собственной сетевой синхронизации.

### 10.3. Ограничение native-слоя

Файлы групп содержат объявления и hash-таблицы штатных GTA native-функций. Наличие функций `CREATE_PED(..., isNetwork, ...)`, `NETWORK_PLAYER_ID_TO_INT`, `NETWORK_SET_SCRIPT_IS_SAFE_FOR_NETWORK_GAME` или `START_NETWORKED_PARTICLE_FX...` означает, что код умеет вызывать встроенные точки входа игры. Это не доказывает наличие сетевого транспорта MultiPlayer. В репозитории нет слоя, который передает созданные сущности другому процессу или преобразует их состояние в сетевые пакеты.

## 11. Пулы, структуры и работа с памятью игры

### 11.1. Динамические структуры

`GameEntityStructure` описывает минимум полей сущности: occupied info по `0x10` и type по `0x28` ([`GameStructure.h`](../MultiPlayer/Game/GameStructure.h#L13-L39)). Педы, объекты, pickup и транспорт используют общий `IGameEntityStructure`, где вложенная сущность находится по нулевому смещению ([строки 44-135](../MultiPlayer/Game/GameStructure.h#L44-L135)).

### 11.2. Пулы

`GamePool` предоставляет типизированные доступы к entity, ped, object, pickup и vehicle ([`GamePool.h`](../MultiPlayer/Game/GamePool.h#L346-L380)). Для обычного пула используются `data`, bitmap, max count и размер элемента; итератор пропускает незанятые элементы. Для транспорта используется отдельный пул указателей и bitmap ([`GamePool.h`](../MultiPlayer/Game/GamePool.h#L113-L180), [строки 233-339](../MultiPlayer/Game/GamePool.h#L233-L339)).

В `Update1::InputHandler1` клавиша `O` демонстрирует обход пулов педов и машин, чтение типа сущности и получение ID из памяти ([`main.cpp`](../MultiPlayer/main.cpp#L230-L273)). Это диагностический код, а не сетевой менеджер игроков.

### 11.3. Риски

Большая часть структур описана вручную смещениями и указателями внутриигровой памяти. Ошибка версии, неверный pattern или изменение layout может привести к чтению/записи по неправильному адресу. В проекте есть проверки найденных паттернов, но почти нет проверок валидности самих игровых объектов после получения адреса.

## 12. C++ SDK

SDK организован по уровням:

- `SDK::Call` — низкоуровневый вызов native ([`NativeCaller.h`](../MultiPlayer/SDK/NativeCaller.h));
- `Model`, `Entity`, `Ped`, `Vehicle`, `Weapon`, `Bone`, `TaskInvoker` — объектные оболочки;
- `Builder` — фабрики создания педов и транспорта;
- `Hash`-файлы — имена моделей, оружия, педов, костей и транспорта.

Тестовый `Update1` показывает предполагаемый сценарий использования: получение координат игрока, создание педа, выдача оружия, выбор оружия, проигрывание анимации и изменение транспорта ([`main.cpp`](../MultiPlayer/main.cpp#L155-L181), [строки 322-350](../MultiPlayer/main.cpp#L322-L350)). Часть тестов находится под `if (false)` и в рабочем потоке не выполняется.

Файлы [`SDK/API.cpp`](../MultiPlayer/SDK/API.cpp) и [`SDK/World/Entity.cpp`](../MultiPlayer/SDK/World/Entity.cpp) сейчас практически пустые; значительная часть поведения SDK реализована прямо в header-файлах и через native-вызовы.

## 13. Скриптовые языки

### Lua

`Core::Lua_init()` создает каталог `scripts\testLua`, настраивает Lua path вида `directory\?.lua`, создает `LuaContext` и добавляет его в `GameScriptEngine` ([`Core.h`](../MultiPlayer/Core/Core.h#L157-L175)).

Lua получает:

- метатаблицы экспортируемых C++-классов;
- глобальный `Event.addListener`;
- `printw` для оконного сообщения;
- `print` для лога;
- `sleep` для уступки fiber.

Регистрация сделана в [`LuaContext.cpp`](../MultiPlayer/Core/ScriptLang/Lua/LuaContext.cpp#L4-L22). Это рабочая концепция расширения через Lua, но в отчетном срезе нет примеров пользовательских Lua-файлов в каталоге `scripts`.

### JavaScript/V8

`Core::V8_init()` инициализирует V8 и создает `scripts\test`, но сейчас содержит безусловный `return` до создания `JavaScriptContext` ([`Core.h`](../MultiPlayer/Core/Core.h#L136-L155)). Поэтому автоматическая регистрация JS-контекста фактически отключена.

Сама инфраструктура V8 предусмотрена: модуль исполняет файл, вызывает entry-функцию, экспортирует `module.exports`, поддерживает `require`, `SDK`, `Event.addListener`, `printw` и `print` ([`JavaScriptContext.cpp`](../MultiPlayer/Core/ScriptLang/JavaScript/JavaScriptContext.cpp#L5-L37), [строки 237-295](../MultiPlayer/Core/ScriptLang/JavaScript/JavaScriptContext.cpp#L237-L295)).

## 14. GUI и управление окнами

GUI-слой внутри MultiPlayer использует ImGui и набор header-only окон/виджетов. `GameContext::OnTick()` обрабатывает очередь SDK-событий ([`GUI.h`](../MultiPlayer/GUI/GUI.h#L25-L41)). `WinManager` владеет списком окон, управляет видимостью и удаляет окно через close event ([`GUI.h`](../MultiPlayer/GUI/GUI.h#L46-L94)).

Предусмотрены окна и виджеты для:

- контекстного менеджера;
- редактора скриптов;
- менеджеров пулов педов и транспорта;
- поиска native-функций и анимаций;
- просмотра SDK-классов;
- файлового дерева;
- редактора кода.

В проекте есть также отдельный `GUI_Lib`; его не следует путать с текущим GUI основной DLL. Основной runtime GUI подключается из `MultiPlayer/GUI` и собирается как часть `MultiPlayer.vcxproj` ([список исходников и заголовков](../MultiPlayer/MultiPlayer.vcxproj#L150-L234)).

## 15. Что реально происходит за один игровой кадр

Упрощенная последовательность:

```text
GTA5.exe
  -> оригинальный update
     -> MultiPlayer.GameUpdate::MainUpdateHook
        -> GAME_INIT (только первый раз)
        -> GAME_UPDATE
        -> счетчик FPS
        -> оригинальный update

GTA script Sleep
  -> GameScriptEngine::SleepHook
     -> GAME_SCRIPT_EXECUTE
        -> fibers зарегистрированных контекстов
           -> OnInit (один раз)
           -> отложенные input/UI сообщения
           -> OnTick
           -> возврат в главный fiber

IDXGISwapChain::Present
  -> Direct3D11::PresentHook
     -> GAME_D3D_INIT (только первый раз)
     -> GAME_D3D_PRESENT
        -> ImGui NewFrame
        -> окна и widgets
        -> ImGui Render
     -> оригинальный Present
```

Ключевая особенность: игровые действия должны выполняться из правильного игрового контекста/fiber. Простого вызова native из произвольного Windows-потока недостаточно и потенциально опасно.

## 16. Текущие недоработки и технические риски

1. **Сетевой мультиплеер отсутствует как подсистема.** Нет транспорта, протокола, сервера, клиентов, репликации сущностей и интерполяции.
2. **Поддерживается одна версия игры.** Все сигнатуры и поля относятся к `V141`.
3. **Смешаны runtime и экспериментальный код.** В `main.cpp` присутствуют тестовые надписи, горячие клавиши, `if (false)`, демонстрационные классы `D3D_Present1/2`.
4. **Есть очевидные ошибки жизненного цикла.** Обработчики и контексты создаются через `new`, а полноценное удаление/снятие хуков почти нигде не реализовано; многие `Remove()` пусты.
5. **Есть риск падения GUI.** `Draw` ожидает корректно инициализированные `GameInput::m_hWindow`, Direct3D device/context и swap chain.
6. **Есть риск нарушения памяти.** SDK читает структуры GTA по жестким offsets, а `Memory::Handle` дает прямую запись в адресное пространство.
7. **Порядок D3D-подмены хрупок.** VTable swap chain клонируется вручную, а `m_RenderTargetView` нигде не заполняется.
8. **JavaScript по умолчанию не подключен.** Без удаления раннего `return` в `V8_init()` JS-контекст не регистрируется.
9. **Кэш offsets требует контроля версии.** Формат кэша помечен `v1.4.1`, но привязка к конкретному build игры и проверка всех семантических зависимостей ограничены.
10. **Работа из DllMain и Sleep.** Долгая инициализация/загрузка зависимостей в `DLL_PROCESS_ATTACH` может приводить к deadlock или нестабильности.

Дополнительные проблемы, которые важны при развитии проекта:

- `IGameGenericPool::getCount()` пока всегда возвращает `0`, поэтому нельзя считать этот показатель достоверным ([`GamePool.h`](../MultiPlayer/Game/GamePool.h#L151-L165)).
- объектный пул в текущей модели фактически не доведен до рабочего состояния; в первую очередь проверять следует типизированные pool manager-ы и вызовы `GamePool::Object()` ([`GamePool.h`](../MultiPlayer/Game/GamePool.h#L346-L379)).
- `D3D_Present1::getScriptContext()` и `InputHandler1::getScriptContext()` возвращают `nullptr`; пути, где затем разыменовывается этот указатель, являются потенциальным access violation ([`main.cpp`](../MultiPlayer/main.cpp#L184-L221), [строки 223-228](../MultiPlayer/main.cpp#L223-L228)).
- обработка `GAME_D3D_INIT` в общем callback затем приводит сообщение к типу `GameEventD3DPresentMessage`; это требует исправления до расширения D3D-событий ([`Direct3D11.h`](../MultiPlayer/Game/DirectX/Direct3D11.h#L40-L64)).
- `m_RenderTargetView` объявлен, но не заполняется, а клонированная vtable выделяется без видимого освобождения ([`Direct3D11.h`](../MultiPlayer/Game/DirectX/Direct3D11.h#L112-L124), [строки 156-163](../MultiPlayer/Game/DirectX/Direct3D11.h#L156-L163)).
- native-контекст хранится статически, поэтому параллельные native-вызовы нельзя считать потокобезопасными ([`IGameNative.h`](../MultiPlayer/Game/ScriptEngine/IGameNative.h#L10-L81)).
- JavaScript native bridge не реализован, а часть ошибок JS только комментирует место для исключения ([`Native.h`](../MultiPlayer/SDK/Native.h#L220-L237), [`JavaScriptContext.cpp`](../MultiPlayer/Core/ScriptLang/JavaScript/JavaScriptContext.cpp#L92-L110)).
- часть рабочих демонстраций недостижима из-за `if (false)` и раннего `return` в обработчике клавиши `O` ([`main.cpp`](../MultiPlayer/main.cpp#L251-L281), [строки 283-355](../MultiPlayer/main.cpp#L283-L355)).
- большинство `Remove()` пусты, поэтому перезагрузка или корректная выгрузка DLL не является безопасным поддерживаемым сценарием ([`GameUpdate.h`](../MultiPlayer/Game/GameUpdate.h#L105-L135)).

## 17. Рекомендуемый маршрут изучения исходников

Для нового разработчика оптимальный порядок такой:

1. [`MultiPlayer/main.cpp`](../MultiPlayer/main.cpp#L400-L429) — точка входа.
2. [`MultiPlayer/Core/Core.h`](../MultiPlayer/Core/Core.h#L22-L40) — порядок инициализации.
3. [`MultiPlayer/Game/GameVersionHook.h`](../MultiPlayer/Game/GameVersionHook.h#L39-L105) — набор подсистем версии 141.
4. [`MultiPlayer/Game/GameHookList.h`](../MultiPlayer/Game/GameHookList.h#L27-L105) — кэш и жизненный цикл паттернов.
5. [`MultiPlayer/Utility/Pattern.h`](../MultiPlayer/Utility/Pattern.h#L96-L235) и [`MemoryHandle.h`](../MultiPlayer/Utility/MemoryHandle.h#L527-L652) — как находятся и перехватываются функции.
6. [`MultiPlayer/Game/GameEvent.h`](../MultiPlayer/Game/GameEvent.h#L20-L244) — шина событий и приоритеты.
7. [`MultiPlayer/Game/GameUpdate.h`](../MultiPlayer/Game/GameUpdate.h#L57-L130) — игровой кадр.
8. [`MultiPlayer/Game/ScriptEngine/GameScriptEngine.h`](../MultiPlayer/Game/ScriptEngine/GameScriptEngine.h#L71-L139) — fibers и контексты.
9. [`MultiPlayer/Game/GamePool.h`](../MultiPlayer/Game/GamePool.h#L113-L180) и [`GameStructure.h`](../MultiPlayer/Game/GameStructure.h#L13-L154) — память игровых сущностей.
10. [`MultiPlayer/SDK/Builder.h`](../MultiPlayer/SDK/Builder.h#L12-L160) — удобный уровень создания объектов.
11. [`MultiPlayer/GUI/GUI.h`](../MultiPlayer/GUI/GUI.h#L98-L194) — ImGui и горячие клавиши.
12. [`MultiPlayer/Game/MultiPlayer/GameRemoveSingleElements.h`](../MultiPlayer/Game/MultiPlayer/GameRemoveSingleElements.h#L18-L64) — что именно подавляется ради multiplayer-подобного окружения.

## 18. Итоговая архитектурная формула

```text
Инжектор/loader
    -> MultiPlayer.dll
        -> Core
            -> сигнатурный поиск адресов GTA V
            -> MinHook и игровые хуки
            -> шина событий
            -> fibers script engine
            -> native hash registry
            -> SDK объектов и пулов
            -> ImGui GUI
            -> Lua и заготовка V8
            -> отключение части одиночной логики
```

Проект уже содержит низкоуровневую основу, необходимую для построения multiplayer: контроль игрового кадра, создание сущностей, доступ к пулам, native-вызовы и UI. Но слой, который превращает эти локальные операции в взаимодействие нескольких машин или процессов, пока отсутствует и должен проектироваться отдельно поверх этой основы.
