#pragma once
#include "GhidraAbstractMapper.h"

namespace CE {
	class ProgramModule;
};

namespace CE::Ghidra
{
	using namespace ghidra;

	class Sync
	{
	public:
		Sync(CE::ProgramModule* programModule);

		Client* getClient();

		DataPacketTransferProvider* getDataPacketTransferProvider();

		void load(DataSyncPacket* dataPacket);
	private:
		CE::ProgramModule* m_programModule;
		Client* m_client;
		DataPacketTransferProvider* m_dataPacketTransferProvider;
	};
};