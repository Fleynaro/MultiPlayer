#pragma once
#include "Analyser.h"
#include <Code/Function/Method.h>
#include <DynHook/DynHook.h>
#include <SQLiteCpp/SQLiteCpp.h>
#include <Utility/FileWrapper.h>
#include <Utils/Buffer.h>
#include <Pointer/Pointer.h>

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

	namespace Trigger::Function
	{
		class Trigger;
	};

	class StreamRecordWriter
	{
	public:
		StreamRecordWriter()
		{}

		int getWrittenLength() {
			return getStream().getOffset();
		}

		virtual void write() = 0;

		Buffer::Stream& getStream() {
			return m_bufferStream;
		}

		void setBufferStream(Buffer::Stream bufferStream) {
			m_bufferStream = bufferStream;
		}
	private:
		Buffer::Stream m_bufferStream;
	};

	class StreamRecord
	{
	public:
		StreamRecord(Buffer::Stream* bufferStream, StreamRecordWriter* streamRecordWriter)
			: m_bufferStream(bufferStream), m_streamRecordWriter(streamRecordWriter)
		{}

		void write() {
			writeHeader();
			m_streamRecordWriter->setBufferStream(m_bufferStream);
			m_streamRecordWriter->write();
			writeEnd();
		}
	private:
		void writeHeader() {
			m_size = m_bufferStream->getNext<int>();
			m_bufferStream->write(0);
		}

		void writeEnd() {
			*m_size = m_streamRecordWriter->getWrittenLength();
		}
	protected:
		Buffer::Stream* m_bufferStream;
		StreamRecordWriter* m_streamRecordWriter;
		int* m_size;
	};

	class BufferIterator {
	public:
		BufferIterator(Buffer* buffer)
			: m_buffer(buffer), m_bufferStream(buffer)
		{
			countSize();
		}

		bool hasNext() {//MYTODO: check offset
			return m_curSize > 0 && getOffset() + (UINT)m_curSize <= m_buffer->getContentOffset();
		}

		Buffer::Stream getStream() {
			Buffer::Stream bufferStream = m_bufferStream;
			m_bufferStream.move(m_curSize);
			countSize();
			return bufferStream;
		}

		int getOffset() {
			return m_bufferStream.getOffset();
		}
	private:
		Buffer* m_buffer;
		Buffer::Stream m_bufferStream;
		int m_curSize;

		void countSize() {
			m_curSize = m_bufferStream.read<int>();
		}
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
			enum class Type {
				BeforeCallInfo,
				AfterCallInfo
			};

			struct Header {
				BYTE m_type;
				uint64_t m_uid;
				int m_triggerId;
				int m_funcDefId;
			};

			class CallInfoWriter : public StreamRecordWriter {
			public:
				CallInfoWriter(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
					: m_trigger(trigger), m_hook(hook)
				{}

				void writeHeader(Type type);

				bool writeTypeValue(void* argAddrValue, CE::Type::Type* argType) {
					if (argType->getPointerLvl() > 1) {
						argAddrValue = Address::Dereference(argAddrValue, argType->getPointerLvl() - 1);
						if (argAddrValue == nullptr)
							return false;
					}

					int size = argType->getSize();
					if (argType->isPointer()) {
						size = argType->getBaseType()->getSize();
						//string
					}

					//MYTODO: узнать тип указателя: на стек, на кучу, массив ли?

					if (Address(argAddrValue).canBeRead()) {
						getStream().write((USHORT)size);
						getStream().writeFrom(argAddrValue, size);
						return true;
					}

					return false;
				}
			protected:
				CE::Trigger::Function::Trigger* m_trigger;
				CE::Hook::DynHook* m_hook;

				inline CE::Function::FunctionDefinition* getFunctionDef() {
					return (CE::Function::FunctionDefinition*)m_hook->getUserPtr();
				}
			};

			namespace BeforeCallInfo {
				struct ArgHeader {
					uint64_t m_argExtraBits;
					BYTE m_argCount;
				};

				using ArgBody = BYTE;

				class Writer : public CallInfoWriter {
				public:
					Writer(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
						: CallInfoWriter(trigger, hook)
					{}

					void write() override {
						//write header
						writeHeader(Type::BeforeCallInfo);

						//write argument values
						ArgHeader argHeader;
						argHeader.m_argExtraBits = 0;
						argHeader.m_argCount = m_hook->getArgCount();
						m_argHeader = getStream().getNext<ArgHeader>();
						getStream().write(argHeader);

						for (int argIdx = 1; argIdx <= m_hook->getArgCount(); argIdx++) {
							writeArgument(argIdx);
						}
					}

				private:
					void writeArgument(int argIdx) {
						auto argValue = m_hook->getArgumentValue(argIdx);
						getStream().write(argValue);
						if (argIdx >= 1 && argIdx <= 4) {
							getStream().write(m_hook->getXmmArgumentValue(argIdx));
						}

						writeArgumentExtra(argIdx, (void*)argValue);
					}

					void writeArgumentExtra(int argIdx, void* argAddrValue) {
						/*
							Могут содержаться в регистре:
							1) Числа
							2) Указатели, массивы, объекты в стеке -> ссылка
							Итог: все представимя в виде числа 8 байтового
							Задача: 8 байт -> массив байт(нач. адрес и размер)
						*/
						auto argType = getFunctionDef()->getDeclaration().getSignature().getArgList()[argIdx - 1];
						if (writeTypeValue(argAddrValue, argType)) {
							m_argHeader->m_argExtraBits |= 0b1 << (argIdx - 1);
						}
					}
				private:
					ArgHeader* m_argHeader;
				};

				class Reader {
				public:
					Reader(Buffer::Stream* bufferStream)
						: m_bufferStream(bufferStream)
					{
						m_argHeader = getStream().readPtr<ArgHeader>();
					}

					struct ArgInfo {
						uint64_t m_value;
						uint64_t m_xmmValue;
						USHORT m_extraDataSize = 0;
						BYTE* m_extraData = nullptr;
						bool m_hasXmmValue = false;
					};

					ArgInfo readArgument() {
						ArgInfo argInfo;

						argInfo.m_value = getStream().read<uint64_t>();
						if (m_curArgIdx >= 1 && m_curArgIdx <= 4) {
							argInfo.m_xmmValue = getStream().read<uint64_t>();
							argInfo.m_hasXmmValue = true;
						}

						if (m_argHeader->m_argExtraBits >> (m_curArgIdx - 1) & 0b1) {
							argInfo.m_extraDataSize = getStream().read<USHORT>();
							argInfo.m_extraData = getStream().readPtr(argInfo.m_extraDataSize);
						}

						m_curArgIdx++;
						return argInfo;
					}

					ArgHeader& getArgHeader() {
						return *m_argHeader;
					}
				private:
					Buffer::Stream m_bufferStream;
					ArgHeader* m_argHeader;
					int m_curArgIdx = 1;

					Buffer::Stream& getStream() {
						return m_bufferStream;
					}
				};
			};
		};

		class BufferSaver {
		public:
			BufferSaver(Buffer* buffer, const std::string& path)
				: m_buffer(buffer), m_path(path)
			{}

			void save() {
				m_isWorking = true;
				m_thread = std::thread(&BufferSaver::handler, this);
				m_thread.detach();
			}

			void handler() {
				std::ofstream output_file(m_path, std::ios::binary);
				if (output_file.is_open()) {
					output_file.write((char*)m_buffer->getData(), m_buffer->getSize());
					output_file.close();
				}

				m_isWorking = false;
			}

			std::atomic<bool> m_isWorking = false;
		private:
			Buffer* m_buffer;
			std::string m_path;
			std::thread m_thread;
		};


		class TriggerBuffer;
		class BufferManager
		{
		public:
			BufferManager(FS::Directory dir, int bufferSizeMb = 3)
				: m_dir(dir), m_bufferSizeMb(bufferSizeMb)
			{
				m_savedBufferCount = m_dir.getItems().size();
			}

			~BufferManager();

			void write(CE::Trigger::Function::Trigger* trigger, StreamRecordWriter* writer);

			void saveTriggerBuffer(int triggerId);

			int m_savedBufferCount;
			int m_bufferSizeMb;
			FS::Directory m_dir;
		private:
			std::map<int, TriggerBuffer*> m_triggerBuffers;
			std::mutex m_bufferMutex;
		};

		class TriggerBuffer
		{
			friend class BufferManager;
		public:
			TriggerBuffer(BufferManager* bufferManager, CE::Trigger::Function::Trigger* trigger, int bufferSizeMb)
				: m_bufferManager(bufferManager), m_trigger(trigger), m_bufferSizeMb(bufferSizeMb)
			{
				createNewBuffer();
			}

			~TriggerBuffer() {
				for (auto saver : m_savers) {
					delete saver;
				}
			}

			void write(StreamRecordWriter* writer) {
				StreamRecord record(&m_bufferStream, writer);
				record.write();

				if (m_currentBuffer->getFreeSpaceSize() == 0) {
					if (getWorkedSaverCount() > 0) {
						m_bufferSizeMb *= 2;
					}
					saveCurBuffer();
					createNewBuffer();
					write(writer);
				}
			}
		private:
			BufferManager* m_bufferManager;
			CE::Trigger::Function::Trigger* m_trigger;
			Buffer* m_currentBuffer;
			Buffer::Stream m_bufferStream;
			std::list<BufferSaver*> m_savers;
			int m_bufferSizeMb;

			int getWorkedSaverCount() {
				int count = 0;
				for (auto saver : m_savers) {
					if (saver->m_isWorking)
						count++;
				}
				return count;
			}

			std::string generateNewName();

			void createNewBuffer() {
				m_currentBuffer = Buffer::Create(m_bufferSizeMb * 1024 * 1024);
				m_bufferStream = Buffer::Stream(m_currentBuffer);
			}

			void saveCurBuffer() {
				auto saver = new BufferSaver(m_currentBuffer, FS::File(m_bufferManager->m_dir, generateNewName()).getFilename());
				saver->save();
				m_savers.push_back(saver);
				m_currentBuffer = nullptr;
			}
		};

		class Collector
		{
		public:
			Collector(FS::Directory dir)
				: m_bufferManager(new BufferManager(dir))
			{}

			~Collector() {
				delete m_bufferManager;
			}

			void addBeforeCallInfo(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
			{
				auto writer = Record::BeforeCallInfo::Writer(trigger, hook);
				m_bufferManager->write(trigger, &writer);
			}

			void addAfterCallInfo(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
			{
				
			}

			BufferManager* getBufferManager() {
				return m_bufferManager;
			}
		private:
			BufferManager* m_bufferManager;
		};



		namespace Analyser
		{
			class IAnalysisProvider {
			public:
				virtual void handle(Record::Header& header, Buffer::Stream& bufferStream) = 0;
			};

			class SignatureAnalysisProvider : public IAnalysisProvider {
			public:

				void handle(Record::Header& header, Buffer::Stream& bufferStream) override {
					auto type = (Record::Type)header.m_type;
					if (type == Record::Type::BeforeCallInfo) {
						handleBeforeCallInfo(bufferStream);
					}
					else {
						handleAfterCallInfo(bufferStream);
					}
				}

				void handleBeforeCallInfo(Buffer::Stream& bufferStream) {
					Record::BeforeCallInfo::Reader reader(&bufferStream);
					auto& argHeader = reader.getArgHeader();

					for (int i = 0; i < argHeader.m_argCount; i++)
					{
						auto argInfo = reader.readArgument();
						auto value = argInfo.m_value;
						float val = (float&)argInfo.m_xmmValue;
						val = 0.0;
					}
				}

				void handleAfterCallInfo(Buffer::Stream& bufferStream) {

				}
			private:
				std::mutex m_dataMutex;
			};

			class ITaskMonitor
			{
			public:
				virtual bool isWorking() {
					return getProgress() != 1.0;
				}
				virtual float getProgress() = 0;
			};

			class BufferAnalyser : public ITaskMonitor {
			public:
				BufferAnalyser(Buffer* buffer)
					: m_buffer(buffer)
				{}

				void startAnalysis() {
					m_progress = 0.0;
					m_thread = std::thread(&BufferAnalyser::analyse, this);
					m_thread.detach();
				}

				void setAnalysisProvider(IAnalysisProvider* analysisProvider) {
					m_analysisProvider = analysisProvider;
				}

				float getProgress() override {
					return m_progress;
				}
			private:
				Buffer* m_buffer;
				IAnalysisProvider* m_analysisProvider;
				std::thread m_thread;
				std::atomic<float> m_progress = 1.0;

				void analyse() {
					BufferIterator it(m_buffer);
					while (it.hasNext()) {
						auto stream = it.getStream();
						auto& header = stream.read<Record::Header>();
						m_analysisProvider->handle(header, stream);
						m_progress = float(it.getOffset()) / m_buffer->getContentOffset();
					}
					m_progress = 1.0;
				}
			};

			class Analyser : public ITaskMonitor {
			public:
				Analyser(IAnalysisProvider* analysisProvider)
					: m_analysisProvider(analysisProvider)
				{}

				void startAnalysis() {
					for (auto it : m_bufferAnaylysers) {
						it->startAnalysis();
					}
				}

				void addBuffer(Buffer* buffer) {
					auto bufferAnalyser = new BufferAnalyser(buffer);
					m_bufferAnaylysers.push_back(bufferAnalyser);
				}

				float getProgress() override {
					float totalPorgress = 0.0;
					for (auto it : m_bufferAnaylysers) {
						totalPorgress += it->getProgress();
					}
					return totalPorgress / m_bufferAnaylysers.size();
				}
			private:
				std::list<BufferAnalyser*> m_bufferAnaylysers;
				IAnalysisProvider* m_analysisProvider;
			};
		};
	};
};