#pragma once
#include "Analyser.h"
#include <Code/Function/Method.h>
#include <DynHook/DynHook.h>
#include <SQLiteCpp/SQLiteCpp.h>
#include <Utility/FileWrapper.h>
#include <Utils/Buffer.h>

using namespace SQLite;

namespace CE
{
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





	class StatManager;

	namespace Trigger::Function
	{
		class Trigger;
	};

	class StreamRecord
	{
	public:
		StreamRecord(Buffer::Stream* bufferStream)
			: m_bufferStream(bufferStream)
		{}

		void write() {
			writeHeader();
			writeBody();
			writeEnd();
		}
	private:
		void writeHeader() {
			m_sizeValue = getStream().getNext();
			getStream().write(0);
		}

		void writeEnd() {
			auto writtenLength = getStream().getWrittenLength();
			getStream().setNext(m_sizeValue);
			getStream().write(writtenLength);
		}
	protected:
		virtual void writeBody() = 0;
		Buffer::Stream& getStream() {
			return *m_bufferStream;
		}

		Buffer::Stream* m_bufferStream;
		BYTE* m_sizeValue;
	};

	namespace Stat::Function
	{
		struct CallInfo {
			enum Type {
				Before,
				After
			};
		};

		namespace Record
		{
			enum class Id {
				BeforeCallInfo,
				AfterCallInfo
			};

			/*class Type {

			public:
				enum Id {
					Bool,
					Char,
					Byte,
					Short,
					Int,
					Long,
					Object
				};

				static Id Get(CE::Type::Type* type) {
					if (type->getGroup() == CE::Type::Type::Class)
						return Object;

					switch (type->getSize()) {
					case 1:
						if(CE::Type::SystemType::GetBasicTypeOf(type->getBaseType()) == CE::Type::Type::)
						break;
					}
				}
			};*/

			namespace BeforeCallInfo {
				class Writer {
				public:
					Writer(Buffer::Stream* bufferStream, CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
						: m_bufferStream(bufferStream), m_trigger(trigger), m_hook(hook)
					{}

					void write() {
						writeHeader();

					}

				private:
					void writeHeader() {
						(*m_bufferStream)
							.write((BYTE)Id::BeforeCallInfo)
							.write(m_hook->getUID())
							.write(m_trigger->getId())
							.write(getFunctionDef()->getId())
							.write(m_hook->getArgCount());
					}

					void writeArgumentType(int argIdx) {
						auto argType = getFunctionDef()->getDeclaration().getSignature().getArgList()[argIdx - 1];
						int typeSize = argType->getSize();

						if (CE::Type::SystemType::GetNumberSetOf(argType->getBaseType()) == CE::Type::SystemType::Real) {
							m_bufferStream->write(8);
							m_bufferStream->write(m_hook->getXmmArgumentValue(argIdx));
							return;
						}

						m_bufferStream->write(typeSize);
						switch (typeSize) {
						case 1:
							m_bufferStream->write((BYTE)m_hook->getArgumentValue(argIdx));
							break;
						case 2:
							m_bufferStream->write((BYTE)m_hook->getArgumentValue(argIdx));
							break;
						case 4:
							m_bufferStream->write((BYTE)m_hook->getArgumentValue(argIdx));
							break;
						case 8:
							m_bufferStream->write((BYTE)m_hook->getArgumentValue(argIdx));
							break;
						}
					}

					void getArgumentTypeCode(Type::Type* type) {
						/*BYTE code;

						if (type->getGroup() == Type::Type::Class) {
							code = 
						}
						auto basicType = Type::SystemType::GetBasicTypeOf(type->getBaseType());
						switch (type->getBaseType()->getId()) {
						case Type::Bool:
						}
						
						return code;*/
					}
				private:
					Buffer::Stream* m_bufferStream;
					CE::Trigger::Function::Trigger* m_trigger;
					CE::Hook::DynHook* m_hook;

					inline CE::Function::FunctionDefinition* getFunctionDef() {
						return (CE::Function::FunctionDefinition*)m_hook->getUserPtr();
					}
				};

				class Reader {
				public:

				};
			};
		};

		/*
			1) запись и чтение - быстрое
			2) разнородные данные

			Запись сделать через условные выражения, т.е. ветвить. данные напрямую берем
			Чтение - КА
		*/


		 

		class CallInfoStreamRecord : public StreamRecord
		{
		public:
			CallInfoStreamRecord(Buffer::Stream* bufferStream, CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
				: StreamRecord(bufferStream), m_trigger(trigger), m_hook(hook)
			{}

			void writeBody() override {
				//getStream().write();
			}

			void readBody() {

			}
		private:
			CE::Trigger::Function::Trigger* m_trigger;
			CE::Hook::DynHook* m_hook;
		};

		class BufferManager
		{
		public:
			BufferManager()

			{}

			Buffer* getCurrentBuffer() {
				return m_currentBuffer;
			}
		private:
			Buffer* m_currentBuffer;
			//save buffers to file
		};

		class Collector
		{
		public:


			inline void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
			{
				
			}


		private:
			BufferManager m_bufferManager;
		};
	};




	namespace Stat::Function2
	{
			template<typename T>
			class ICollector
			{
			public:
				ICollector(StatManager* statManager = nullptr)
					: m_statManager(statManager)
				{}

				~ICollector() {
					if (m_db != nullptr) {
						delete m_db;
					}
				}

				void start() {
					m_thread = std::thread(&ICollector<T>::handler, this);
					m_thread.detach();
				}

				void initDataBase(SQLite::Database* db)
				{
					if (m_db != nullptr) {
						delete m_db;
					}
					m_db = db;
				}

				virtual void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook) = 0;

				int getSize() {
					return m_buffers.size();
				}

				SQLite::Database& getDB() {
					return *m_db;
				}

				virtual void copyStatTo(SQLite::Database& db) {};
				virtual void clear() {}
			protected:
				virtual void handler() = 0;

				std::queue<T> m_buffers;
				std::mutex m_bufferMutex;
				std::mutex m_dbMutex;
				std::thread m_thread;

				StatManager* m_statManager;
				SQLite::Database* m_db = nullptr;
			};

			template<typename B, typename G = ICollector<B>>
			class AbstractManager
			{
			public:
				inline void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
				{
					selectGarbager1()->add(trigger, hook);
					//m_counter++;
				}

				ICollector<B>* selectGarbager1() {
					ICollector<B>* result = nullptr;
					int size = INT_MAX;
					for (ICollector<B>* garbager : m_garbagers) {
						if (garbager->getSize() < size) {
							result = garbager;
							size = garbager->getSize();
						}
					}
					return result;
				}

				ICollector<B>* selectGarbager2() {
					return m_garbagers[m_counter % m_garbagers.size()];
				}

				void copyStatTo(SQLite::Database& db)
				{
					for (auto it : m_garbagers) {
						it->copyStatTo(db);
						it->clear();
					}
				}

				void addCollector(ICollector<B>* garbager)
				{
					m_garbagers.push_back(garbager);
				}
			protected:
				std::vector<ICollector<B>*> m_garbagers;
				std::atomic<uint64_t> m_counter = 0;
			};

			namespace Args
			{
				class Buffer
				{
				public:
					uint64_t m_uid = 0;
					uint64_t m_args[12] = { 0 };
					uint64_t m_xmm_args[4] = { 0 };
					CE::Hook::DynHook* m_hook = nullptr;
					CE::Trigger::Function::Trigger* m_trigger = nullptr;

					Buffer(CE::Hook::DynHook* hook, CE::Trigger::Function::Trigger* trigger)
					{
						m_uid = hook->getUID();
						for (int i = 1; i <= hook->getArgCount(); i++) {
							m_args[i - 1] = hook->getArgumentValue(i);
						}
						if (hook->isXmmSaved()) {
							for (int i = 1; i <= min(4, hook->getArgCount()); i++) {
								m_xmm_args[i - 1] = hook->getXmmArgumentValue(i);
							}
						}
						m_hook = hook;
						m_trigger = trigger;
					}

					inline CE::Function::Function* getFunction() {
						return (CE::Function::Function*)m_hook->getUserPtr();
					}
				};

				class Collector : public ICollector<Buffer>
				{
				public:
					Collector(StatManager* statManager)
						: ICollector<Buffer>(statManager)
					{}

					void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook) override;

					void handler() override {
						while (true)
						{
							m_bufferMutex.lock();
							if (m_buffers.empty()) {
								m_bufferMutex.unlock();
								Sleep(50);
								continue;
							}

							m_dbMutex.lock();
							SQLite::Transaction transaction(getDB());

							for (int i = 0; i < m_buffers.size(); i++) {
								send(m_buffers.front());
								m_buffers.pop();

								static std::atomic<uint64_t> g_counter = 0;
								g_counter++;
								int c = g_counter;
								if (c % 10000 == 0) {
									printf("\n%i) Args", c);
								}
							}
							m_bufferMutex.unlock();


							transaction.commit();
							m_dbMutex.unlock();
							Sleep(30);
						}
					}

					void copyStatTo(SQLite::Database& db)
					{
						m_dbMutex.lock();
						{
							SQLite::Statement query(db, "ATTACH DATABASE ?1 AS call_before");
							query.bind(1, getDB().getFilename());
							query.exec();
						}

						{
							SQLite::Statement query(db, "INSERT INTO sda_call_before SELECT * FROM call_before.sda_call_before");
							query.exec();
						}

						{
							SQLite::Statement query(db, "INSERT INTO sda_call_args SELECT * FROM call_before.sda_call_args");
							query.exec();
						}

						{
							SQLite::Statement query(db, "DETACH DATABASE call_before");
							query.exec();
						}
						m_dbMutex.unlock();
					}

					void clear() override
					{
						{
							SQLite::Statement query(getDB(), "DELETE FROM sda_call_before");
							query.exec();
						}
						{
							SQLite::Statement query(getDB(), "DELETE FROM sda_call_args");
							query.exec();
						}
						{
							SQLite::Statement query(getDB(), "VACUUM");
							query.exec();
						}
					}

					void send(Buffer& buffer);
				};

				class Manager : public AbstractManager<Buffer, Collector> {};
			};

			namespace Ret
			{
				class Buffer
				{
				public:
					uint64_t m_uid = 0;
					uint64_t m_ret = 0;
					uint64_t m_xmm_ret = 0;
					CE::Hook::DynHook* m_hook = nullptr;
					CE::Trigger::Function::Trigger* m_trigger = nullptr;

					Buffer(CE::Hook::DynHook* hook, CE::Trigger::Function::Trigger* trigger)
					{
						m_uid = hook->getUID();
						m_ret = hook->getReturnValue();
						m_xmm_ret = hook->getXmmReturnValue();
						m_hook = hook;
						m_trigger = trigger;
					}

					inline CE::Function::Function* getFunction() {
						return (CE::Function::Function*)m_hook->getUserPtr();
					}
				};

				class Collector : public ICollector<Buffer>
				{
				public:
					Collector(StatManager* statManager)
						: ICollector<Buffer>(statManager)
					{}

					void add(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook) override;

					void handler() override {
						while (true)
						{
							m_bufferMutex.lock();
							if (m_buffers.empty()) {
								m_bufferMutex.unlock();
								Sleep(50);
								continue;
							}
							m_dbMutex.lock();
							SQLite::Transaction transaction(getDB());

							for (int i = 0; i < m_buffers.size(); i++) {
								send(m_buffers.front());
								m_buffers.pop();

								static std::atomic<uint64_t> g_counter = 0;
								g_counter++;
								int c = g_counter;
								if (c % 10000 == 0) {
									printf("\n%i) Ret", c);
								}
							}
							m_bufferMutex.unlock();

							transaction.commit();
							m_dbMutex.unlock();
							Sleep(30);
						}
					}

					void copyStatTo(SQLite::Database& db)
					{
						m_dbMutex.lock();
						{
							SQLite::Statement query(db, "ATTACH DATABASE ?1 AS call_after");
							query.bind(1, getDB().getFilename());
							query.exec();
						}

						{
							SQLite::Statement query(db, "INSERT INTO sda_call_after SELECT * FROM call_after.sda_call_after");
							query.exec();
						}

						{
							SQLite::Statement query(db, "DETACH DATABASE call_after");
							query.exec();
						}
						m_dbMutex.unlock();
					}

					void clear() override
					{
						{
							SQLite::Statement query(getDB(), "DELETE FROM sda_call_after");
							query.exec();
						}
						{
							SQLite::Statement query(getDB(), "VACUUM");
							query.exec();
						}
					}

					void send(Buffer& buffer);
				};

				class Manager : public AbstractManager<Buffer, Collector> {};
			};

			class StatInfo
			{
			public:
				StatInfo()
				{}

				struct Value
				{
					CE::Type::SystemType::Set m_set = CE::Type::SystemType::Undefined;
					CE::Type::SystemType::Types m_typeId = CE::Type::SystemType::Void;
					Analyser::Histogram* m_histogram = nullptr;

					Value() = default;

					Value(CE::Type::SystemType::Set set, CE::Type::SystemType::Types typeId, Analyser::Histogram* histogram)
						: m_set(set), m_typeId(typeId), m_histogram(histogram)
					{}
				};

				void addArgument(Value value) {
					m_args.push_back(value);
				}

				void setReturnValue(const Value& value) {
					m_ret = value;
				}

				Value& getArgument(int index) {
					return m_args[index];
				}

				Value& getReturnValue() {
					return m_ret;
				}

				void debugShow()
				{
					printf("\nStatistic of the function\n\nReturn value: ");
					getReturnValue().m_histogram->debugShow();
					for (int i = 0; i < m_args.size(); i++) {
						printf("\nArgument %i: ", i + 1);
						if (getArgument(i).m_set != CE::Type::SystemType::Undefined)
							getArgument(i).m_histogram->debugShow();
					}
				}
			private:
				std::vector<Value> m_args;
				Value m_ret;
			};

			class Account
			{
			public:
				Account(SQLite::Database* db, CE::Function::Function* function)
					: m_db(db), m_function(function)
				{}

				struct CallInfo
				{
					uint64_t m_uid;
					uint64_t m_args[12];
					uint64_t m_xmm_args[4];
					uint64_t m_ret;
					uint64_t m_xmm_ret;
				};

				void iterateCalls(std::function<void(CallInfo& info)> handler, CE::Trigger::Function::Trigger* trigger, int page, int pageSize = 30);

				static StatInfo::Value getValueByAnalysers(Analyser& analyser, Analyser& analyser_xmm, CE::Type::Type* type)
				{
					using namespace CE::Type;
					Analyser& result = analyser;
					if (!analyser.isUndefined() && !analyser_xmm.isUndefined()) {
						if (SystemType::GetNumberSetOf(type) == SystemType::Real) {
							analyser = analyser_xmm;
						}
					}
					else if (!analyser_xmm.isUndefined()) {
						analyser = analyser_xmm;
					}
					return StatInfo::Value(result.getSet(), result.getTypeId(), result.createHistogram());
				}

				StatInfo* createStatInfo(CE::Trigger::Function::Trigger* trigger = nullptr);


				SQLite::Database& getDB() {
					return *m_db;
				}
			private:
				CE::Function::Function* m_function;
				SQLite::Database* m_db;
			};
	};
};