#pragma once
#include "GhidraAbstractMapper.h"

namespace CE {
	class ProgramModule;
};

namespace CE::Ghidra
{
	using namespace ghidra;

	class FunctionDefMapper;
	class Sync
	{
	public:
		FunctionDefMapper* m_functionDefMapper;

		Sync(CE::ProgramModule* programModule);

		~Sync();

		Client* getClient();

		DataPacketTransferProvider* getDataPacketTransferProvider();

		void load(DataPacket* dataPacket);
	private:
		CE::ProgramModule* m_programModule;
		Client* m_client;
		DataPacketTransferProvider* m_dataPacketTransferProvider;
	};
};