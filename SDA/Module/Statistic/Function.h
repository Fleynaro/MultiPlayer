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
	//MY TODO: ���� ������ ������-�� �������. ���� �����-�������(���������). ���������� �� ��� ������(������ ����� ��� � ������� �������)
	//MY TODO: ���������� ������ �������� ���������� � �������
	//MY TODO: ���������� ��������� � ���������� ������� ��� � ������(������)
	//MY TODO: ����������, ���� ����� ������������ �����

	/*
		1) ������ �������� ����������� �����, ������� ����������� �����������(������)
		2) ������� �� ������ � ���� ����? ��� �� ��������? ���� ���������! 
		3) � �������� � �� ���� ���� - ������ �� ����� �� ������� ������(������ �� ����) - ���� �� �����(�������.)
			3.1) ������ ����� � ���� ����. ��� ������ - ��������� �� �����(������. ������), ��� ������ - !! ��� ���� ����� ������������ ���� � ����� � ������������ !!
				������������������: ������� - �������, �������� - ???
			3.2) ������ � ������ ������. ������ - �������, �������� - �������. ���� �������� - ���������� � ���� �����. ����� ������� � ������ ��� ����. ������ ��� �����. ����
				������������������: ������� - �������, �������� - �������

		Buffer
		��������� ������ [id ������(GUID)] [������ ������] [���-�� ������]
		��������� ����� [������ �����]





		��� ���������� ������������� �� ������������������ ������� �������. ��� �����:
		1) �������� ���������
		2) ������ ����� ������� - workers.
		3) ������ ������������ ���������(������, ��� ���������� �� ��� � ���)
		4) ������ worker �������� �� ����� �������
		5) ����� ���������, ��� ������ worker ����� ����� ����� ������� ����������� ������ � ����. ����� ����� ��������� ����������.
			�������: ������� ��������������� ������, ������� ����� ����� � ����������� �� ������� ���������. ���� worker ��������, �� �������� � ���� ����� � �������� ������� ������(����� ������, � ���� ������� ������� �� ������ � ����)

		!!!������� 2: ���� ���� �������� �����. � ���� ������������ ������. ���� ����� ����������, �� ���������� ��� � ������ �� ������ � ���� � ������ ������. ������ ������� ����� �����. ����� �������� ����� ���������� � ������.


		����� �������� ���� ByteStream. ��� ������ - ����������� ��������� ������ � �������. ��������� ������������, ��� ����� ���������� ������� � ������, ��� �������!
		���������:  [��� ������: before/after call] [id ��������] [id �������] [unixtime] [guid] [������ ������ ���� ����� ����: ���� �� ������, ���� �� ����,������ - ����� ��� ������]
					before: [���-�� ���������� N] [������ �����(byte,int,char,object) ��� ������� ��������� + [pointer/not pointer] N - 4 ����] [���� ��������� N]
					�������� ����� int - 4 �����
					�������� char[32](��� pointer, ��������� �� ������) - [����� �������] [����� ��������] [raw string]
					�������� float[4] - �� ��, ��� � ������. ��� ������. ����. ����� ��������� 65535
					...
					����������� ���������� �������� ����� ������� �������

		� ����� � ��� ����� �����, ��� ����� ���� ������-�������. ������� ���������� ���� ������:
		1) ������ ����� ��������
		2) ������ �����
		3) ������� ��������: �������� ��� ���� ������ ���������, ��� ��������� � �.�
		4) ����������� �� �����-�� �������� � �����(������)

		��� ������� ���� ������� ���� �����, � ������� ���� ����������. ��������� ����� ��������� � ��
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

					//MYTODO: ������ ��� ���������: �� ����, �� ����, ������ ��?

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
							����� ����������� � ��������:
							1) �����
							2) ���������, �������, ������� � ����� -> ������
							����: ��� ����������� � ���� ����� 8 ���������
							������: 8 ���� -> ������ ����(���. ����� � ������)
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