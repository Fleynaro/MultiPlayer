#include "GhidraDataPacket.h"
#include "GhidraClient.h"

using namespace CE;
using namespace CE::Ghidra;

DataPacketTransferProvider::DataPacketTransferProvider(Client* client)
	: m_client(client)
{
	m_functionServiceClient = new function::FunctionManagerServiceClient(
		std::shared_ptr<TMultiplexedProtocol>(new TMultiplexedProtocol(client->m_protocol, "FunctionManager")));
}

DataPacketTransferProvider::~DataPacketTransferProvider() {
	delete m_functionServiceClient;
}

void DataPacketTransferProvider::sendDataPacket(DataPacket* dataPacket) {
	Transport tr(m_client);
	m_functionServiceClient->push(dataPacket->m_functions);
}

void DataPacketTransferProvider::recievedDataPacket(DataPacket* dataPacket)
{
	Transport tr(m_client);
	m_functionServiceClient->pull(dataPacket->m_functions, std::map<function::Id, function::Hash>());
}
