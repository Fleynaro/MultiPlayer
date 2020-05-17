#pragma once
#include "GhidraAbstractMapper.h"
#include "GhidraClient.h"

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

		~Sync();

		ProgramModule* getProgramModule();

		Client* getClient();

		packet::DataSyncPacketManagerServiceClient* getDataSyncPacketManagerServiceClient();
	private:
		CE::ProgramModule* m_programModule;
		Client* m_client;
		packet::DataSyncPacketManagerServiceClient* m_dataSyncPacketManagerServiceClient;
	};
};