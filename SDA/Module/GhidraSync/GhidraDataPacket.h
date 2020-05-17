#pragma once
#include "GhidraObject.h"
#include "FunctionManagerService.h"
#include "DataTypeManagerService.h"

namespace CE::Ghidra
{
	using namespace ghidra;

	struct DataPacket
	{
	};

	struct DataSyncPacket : DataPacket
	{
		std::vector<function::SFunction> m_functions;
		std::vector<datatype::SDataTypeTypedef> m_typedefs;
		std::vector<datatype::SDataTypeEnum> m_enums;
		std::vector<datatype::SDataTypeStructure> m_structs;
		std::vector<datatype::SDataTypeClass> m_classes;
	};

	class Client;
	class DataPacketTransferProvider
	{
	public:
		DataPacketTransferProvider(Client* client);

		~DataPacketTransferProvider();

		void sendDataPacket(DataSyncPacket* dataPacket);

		void recievedDataPacket(DataSyncPacket* dataPacket);

	private:
		Client* m_client;
		function::FunctionManagerServiceClient* m_functionServiceClient;
		datatype::DataTypeManagerServiceClient* m_datatypeServiceClient;
	};
};