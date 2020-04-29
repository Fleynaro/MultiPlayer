#pragma once
#include "Record/BeforeCallInfo.h"
#include "CollectingBufferSaver.h"

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