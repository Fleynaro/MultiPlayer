#pragma once
#include "Record/BeforeCallInfo.h"
#include "CollectingBufferSaver.h"

//MY TODO: есть буферы какого-то размера. Есть класс-фабрика(аллокатор). Определить ид для буфера(синхра между ОЗУ и внешней памятью)
//MY TODO: определить формат хранения заголовков в буферах
//MY TODO: обеспечить интерфейс к нескольким буферам как к одному(список)
//MY TODO: определить, чему будет принадлежать буфер

/*
	1) одному триггеру принадлежит буфер, который динамически расширяется(список)
	2) сливать ли буфера в один файл? как по скорости? надо проверить!
	3) у триггера в БД есть поле - ссылка на буфер во внешней памяти(ссылка на файл) - путь до файла(относит.)
		3.1) буферы слиты в один файл. при чтении - разбивать на блоки(произв. доступ), при записи - !! тут надо взять определенный блок в файле и перехаписать !!
			Производительность: вставка - недолго, загрузка - ???
		3.2) буферы в разных файлах. Запись - недолго, загрузка - недолго. Одна проблема - связывание в один буфер. Можно хранить в буфере имя след. буфера как относ. путь
			Производительность: вставка - недолго, загрузка - недолго

	Buffer
	Заголовок буфера [id буфера(GUID)] [размер буфера] [кол-во блоков]
	Заголовок блока [размер блока]





	При разрабокте оттакливаемся от производительности вставки записей. Для этого:
	1) Избегаем мьютексов
	2) Делаем много потоков - workers.
	3) Делаем эффективного менеджера(одного, нет раздедения на арг и рет)
	4) Каждый worker работает со своим буфером
	5) Может случиться, что каждый worker будет потом занят записью содержимого буфера в файл. Тогда будут серьезные подвисания.
		Решение: создать вспомогательные потоки, которые будут спать и просыпаться по запросу менеджера. Если worker заполнен, то забираем у него буфер и передаем спящему потоку(можно одному, у него очередь буферов на запись в файл)

	!!!ВАРИАНТ 2: есть один активный буфер. В него производятся записи. Если буфер заполнился, то отправляем его в очердь на запись в файл в разные потоки. Просто создаем поток новый. Новый активный буфер выделяется в памяти.


	Также создадим свой ByteStream. Его задача - упаковывать компактно данные о вызовах. Соблюдать выравнивание, ибо лучше записывать словами в память, чем байтами!
	Заголовки:  [тип записи: before/after call] [id триггера] [id функции] [unixtime] [guid] [запись битами сюда общей инфы: есть ли строка, есть ли указ,массив - нужно для поиска]
				before: [кол-во аргументов N] [список типов(byte,int,char,object) для каждого аргумента + [pointer/not pointer] N - 4 бита] [сами аргументы N]
				аргумент число int - 4 байта
				аргумент char[32](это pointer, проверяем на массив) - [адрес массива] [число символов] [raw string]
				аргумент float[4] - то же, что и вверху. это массив. макс. число элементов 65535
				...
				опционально записываем фрагмент стека нужного размера

	В итоге у нас будет папка, где будет куча файлов-буферов. Сделать анализатор этих файлов:
	1) Анализ типов значений
	2) Анализ строк
	3) Аанализ объектов: например где этот объект вызывался, где изменялся и т.д
	4) Встречалось ли какое-то значение в стеке(строка)

	Для каждого типа анализа свой класс, у каждого свои результаты. Некоторые можно сохранить в БД
*/


namespace CE::Stat::Function
{
	class TriggerBuffer;
	//managing collecting and storing of statistic
	class BufferManager
	{
	public:
		BufferManager(FS::Directory dir, int bufferSizeMb = 1);

		~BufferManager();

		//select needed buffer for the trigger and add record into that using StreamRecordWriter
		void write(CE::Trigger::Function::Trigger* trigger, StreamRecordWriter* writer);

		void saveTriggerBuffer(int triggerId);

		int m_savedBufferCount;
		int m_bufferSizeMb;
		FS::Directory m_dir;
	private:
		std::map<int, TriggerBuffer*> m_triggerBuffers;
		std::mutex m_bufferMutex;
	};

	//collecting statistic within a trigger scope
	class TriggerBuffer
	{
		friend class BufferManager;
	public:
		TriggerBuffer(BufferManager* bufferManager, CE::Trigger::Function::Trigger* trigger, int bufferSizeMb);

		~TriggerBuffer();

		//add record using StreamRecordWriter. if needed the buffer of the trigger can be saved into external memory
		void write(StreamRecordWriter* writer);
	private:
		BufferManager* m_bufferManager;
		CE::Trigger::Function::Trigger* m_trigger;
		Buffer* m_currentBuffer;
		Buffer::Stream m_bufferStream;
		std::list<BufferSaver*> m_savers;
		int m_bufferSizeMb;

		int getWorkedSaverCount();

		std::string generateNewName();

		//allocate new memory to store statistic temporally
		void createNewBuffer();

		//save current buffer into external memory
		void saveCurBuffer();
	};

	//collecting different statistic about calling functions hooked by a trigger
	class Collector
	{
	public:
		Collector(FS::Directory dir);

		~Collector();

		//add record described calling(before) the function into the collector
		void addBeforeCallInfo(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook);

		//add record described calling(after) the function into the collector
		void addAfterCallInfo(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook);

		BufferManager* getBufferManager();
	private:
		BufferManager* m_bufferManager;
	};
};