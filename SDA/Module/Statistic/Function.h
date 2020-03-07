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
		StreamRecordWriter(Buffer::Stream* bufferStream)
			: m_bufferStream(bufferStream)
		{}

		int getWrittenLength() {
			return getStream().getOffset();
		}

		virtual void write() = 0;

		Buffer::Stream& getStream() {
			return m_bufferStream;
		}
	private:
		Buffer::Stream m_bufferStream;
	};

	class StreamRecord
	{
	public:
		StreamRecord(StreamRecordWriter* streamRecordWriter)
			: m_streamRecordWriter(streamRecordWriter)
		{}

		void write() {
			writeHeader();
			m_streamRecordWriter->write();
			writeEnd();
		}
	private:
		void writeHeader() {
			m_size = m_streamRecordWriter->getStream().getNext<int>();
			m_streamRecordWriter->getStream().write(0);
		}

		void writeEnd() {
			*m_size = m_streamRecordWriter->getWrittenLength();
		}
	protected:
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
			return m_curSize > 0 && m_bufferStream.getOffset() + (UINT)m_curSize <= m_buffer->m_header.m_currentOffset;
		}

		Buffer::Stream getStream() {
			Buffer::Stream bufferStream = m_bufferStream;
			m_bufferStream.move(m_curSize);
			countSize();
			return bufferStream;
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
				CallInfoWriter(Buffer::Stream* bufferStream, CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
					: StreamRecordWriter(bufferStream), m_trigger(trigger), m_hook(hook)
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
					Writer(Buffer::Stream* bufferStream, CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
						: CallInfoWriter(bufferStream, trigger, hook)
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

		class BufferManager
		{
		public:
			BufferManager(FS::Directory dir, int bufferSizeMb = 3)
				: m_dir(dir), m_bufferSizeMb(bufferSizeMb)
			{
				createNewBuffer();
				m_savedBufferCount = m_dir.getItems().size();
			}

			~BufferManager() {
				saveCurBuffer();

				while (getWorkedSaverCount() > 0) {
					Sleep(100);
				}

				for (auto saver : m_savers) {
					delete saver;
				}
			}

			void write(StreamRecordWriter* writer) {
				StreamRecord record(writer);
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

			void test() {
				BufferIterator it(m_currentBuffer);
				while (it.hasNext()) {
					auto stream = it.getStream(); //set to field of analyser
					auto& header = stream.read<Record::Header>();

					if ((Record::Type)header.m_type == Record::Type::BeforeCallInfo) //call method beforeCallInfo(reader)
					{
						Record::BeforeCallInfo::Reader reader(&stream);
						auto& argHeader = reader.getArgHeader();

						for (int i = 0; i < argHeader.m_argCount; i++)
						{
							auto argInfo = reader.readArgument();
							auto value = argInfo.m_value;
							float val = (float&)argInfo.m_xmmValue;
							val = 0.0;
						}
					}
				}
				saveCurBuffer();
			}

			inline Buffer::Stream* getStream() {
				return &m_bufferStream;
			}
		private:
			int m_bufferSizeMb;
			Buffer* m_currentBuffer;
			Buffer::Stream m_bufferStream;
			std::list<BufferSaver*> m_savers;
			FS::Directory m_dir;
			int m_savedBufferCount;

			int getWorkedSaverCount() {
				int count = 0;
				for (auto saver : m_savers) {
					if (saver->m_isWorking)
						count++;
				}
				return count;
			}

			std::string generateNewName() {
				auto number = std::to_string(10000 + m_savedBufferCount++);
				return "buffer_" + number + ".data";
			}
			
			void saveCurBuffer() {
				auto saver = new BufferSaver(m_currentBuffer, FS::File(m_dir, generateNewName()).getFilename());
				saver->save();
				m_savers.push_back(saver);
				m_currentBuffer = nullptr;
			}

			void createNewBuffer() {
				m_currentBuffer = Buffer::Create(m_bufferSizeMb * 1024 * 1024);
				m_bufferStream = Buffer::Stream(m_currentBuffer);
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
				m_bufferMutex.lock();
				auto writer = Record::BeforeCallInfo::Writer(m_bufferManager->getStream(), trigger, hook);
				m_bufferManager->write(&writer);
				m_bufferMutex.unlock();


				static int a = 1;
				if (a == 3) {
					m_bufferManager->test();
				}
				a++;
			}

			void addAfterCallInfo(CE::Trigger::Function::Trigger* trigger, CE::Hook::DynHook* hook)
			{
				m_bufferMutex.lock();

				m_bufferMutex.unlock();
			}
		private:
			BufferManager* m_bufferManager;
			std::mutex m_bufferMutex;
		};
	};
};