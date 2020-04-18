#pragma once
#include <Code/Code.h>
#include <DynHook/DynHook.h>
#include <Address/Address.h>
#include <Utils/BufferStreamRecorder.h>


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


namespace CE {
	namespace Trigger::Function
	{
		class Trigger;
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

				static bool writeTypeValue(Buffer::Stream& bufferStream, void* argAddrValue, CE::Type::Type* argType) {
					//MYTODO: 1) ������ ���������� 2) ������ ����� 3) ��������� �� ��������� 4) ��������� 5) �� ���������(� �����)
					//MYTODO: ������ ��� ���������: �� ����, �� ����, ������ ��?

					//Block 1: point to the begining of the object
					if (argType->getPointerLvl() > 1) {
						argAddrValue = Address::Dereference(argAddrValue, argType->getPointerLvl() - 1);
						if (argAddrValue == nullptr)
							return false;
					}

					if (!Address(argAddrValue).canBeRead())
						return false;

					//Block 2: calculate size of the object
					int size;
					if (argType->isArrayOfObjects()) {
						size = argType->getSize();
					}
					else if (argType->isString()) {
						char* str = (char*)argAddrValue;
						size = 0;
						while (size < 100 && str[size] != '\0')
							size++;
					}
					else {
						size = argType->getBaseType()->getSize();
					}

					if (size == 0)
						return false;

					bufferStream.write((USHORT)size);
					bufferStream.writeFrom(argAddrValue, size);
					return true;
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
						auto& argTypes = getFunctionDef()->getDeclaration().getSignature().getArgList();
						if (argIdx > argTypes.size())
							return;
						if (writeTypeValue(getStream(), argAddrValue, argTypes[argIdx - 1])) {
							m_argHeader->m_argExtraBits |= uint64_t(0b1) << (argIdx - 1);
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
			BufferManager(FS::Directory dir, int bufferSizeMb = 1)
				: m_dir(dir), m_bufferSizeMb(bufferSizeMb)
			{
				//MYTODO: max id
				m_savedBufferCount = static_cast<int>(m_dir.getItems().size());
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

				try {
					record.write();
				}
				catch (const BufferOverflowException&) {
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
	};
};