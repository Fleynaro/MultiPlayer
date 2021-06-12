#include "GhidraSync.h"
#include <Manager/FunctionManager.h>
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::Ghidra;

Sync::Sync(CE::Project* programModule)
	: m_programModule(programModule)
{
	m_client = new Client;
	m_dataSyncPacketManagerServiceClient = new packet::DataSyncPacketManagerServiceClient(
		std::shared_ptr<TMultiplexedProtocol>(new TMultiplexedProtocol(m_client->m_protocol, "DataSyncPacketManager")));
}

Sync::~Sync() {
	delete m_client;
	delete m_dataSyncPacketManagerServiceClient;
}

Project* Sync::getProject() {
	return m_programModule;
}

Client* Sync::getClient() {
	return m_client;
}

packet::DataSyncPacketManagerServiceClient* Sync::getDataSyncPacketManagerServiceClient() {
	return m_dataSyncPacketManagerServiceClient;
}