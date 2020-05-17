#include "GhidraDataPacket.h"
#include "GhidraClient.h"

using namespace CE;
using namespace CE::Ghidra;

DataPacketTransferProvider::DataPacketTransferProvider(Client* client)
	: m_client(client)
{
	m_functionServiceClient = new function::FunctionManagerServiceClient(
		std::shared_ptr<TMultiplexedProtocol>(new TMultiplexedProtocol(client->m_protocol, "FunctionManager")));
	m_datatypeServiceClient = new datatype::DataTypeManagerServiceClient(
		std::shared_ptr<TMultiplexedProtocol>(new TMultiplexedProtocol(client->m_protocol, "DataTypeManager"))
	);
}

DataPacketTransferProvider::~DataPacketTransferProvider() {
	delete m_functionServiceClient;
	delete m_datatypeServiceClient;
}

void DataPacketTransferProvider::sendDataPacket(DataSyncPacket* dataPacket) {
	Transport tr(m_client);
	m_functionServiceClient->push(dataPacket->m_functions);
	m_datatypeServiceClient->pushTypedefs(dataPacket->m_typedefs);
	m_datatypeServiceClient->pushEnums(dataPacket->m_enums);
	m_datatypeServiceClient->pushStructures(dataPacket->m_structs);
	m_datatypeServiceClient->pushClasses(dataPacket->m_classes);
}

void DataPacketTransferProvider::recievedDataPacket(DataSyncPacket* dataPacket)
{
	Transport tr(m_client);
	m_functionServiceClient->pull(dataPacket->m_functions);
	m_datatypeServiceClient->pullTypedefs(dataPacket->m_typedefs);
	m_datatypeServiceClient->pullEnums(dataPacket->m_enums);
	m_datatypeServiceClient->pullStructures(dataPacket->m_structs);
	m_datatypeServiceClient->pullClasses(dataPacket->m_classes);
}
