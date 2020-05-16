#pragma once
#include "GhidraObject.h"
#include "FunctionManagerService.h"

namespace CE::Ghidra
{
	using namespace ghidra;
	struct DataPacket
	{
		std::vector<function::SFunction> m_functions;
	};

	class Client;
	class DataPacketTransferProvider
	{
	public:
		DataPacketTransferProvider(Client* client);

		~DataPacketTransferProvider();

		void sendDataPacket(DataPacket* dataPacket);

		void recievedDataPacket(DataPacket* dataPacket);

	private:
		Client* m_client;
		function::FunctionManagerServiceClient* m_functionServiceClient;
	};
};