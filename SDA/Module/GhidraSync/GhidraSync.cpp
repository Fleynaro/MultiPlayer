#include "GhidraSync.h"
#include "GhidraClient.h"
#include "Mappers/GhidraFunctionDefMapper.h"
#include <Manager/ProgramModule.h>

using namespace CE;
using namespace CE::Ghidra;

Sync::Sync(CE::ProgramModule* programModule)
	: m_programModule(programModule)
{
	m_client = new Client;
	m_dataPacketTransferProvider = new DataPacketTransferProvider(m_client);
	m_functionDefMapper = new FunctionDefMapper(m_programModule->getFunctionManager());
}

Sync::~Sync() {
	delete m_functionDefMapper;
}

Client* Sync::getClient() {
	return m_client;
}

DataPacketTransferProvider* Sync::getDataPacketTransferProvider() {
	return m_dataPacketTransferProvider;
}

void Sync::load(DataPacket* dataPacket) {
	m_functionDefMapper->load(dataPacket);
}
