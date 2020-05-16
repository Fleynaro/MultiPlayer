#include "GhidraSync.h"
#include "GhidraClient.h"
#include <Manager/FunctionDefManager.h>

using namespace CE;
using namespace CE::Ghidra;

Sync::Sync(CE::ProgramModule* programModule)
	: m_programModule(programModule)
{
	m_client = new Client;
	m_dataPacketTransferProvider = new DataPacketTransferProvider(m_client);
}

Client* Sync::getClient() {
	return m_client;
}

DataPacketTransferProvider* Sync::getDataPacketTransferProvider() {
	return m_dataPacketTransferProvider;
}

void Sync::load(DataPacket* dataPacket) {
	m_programModule->getFunctionManager()->loadFunctionsFrom(dataPacket);
}
