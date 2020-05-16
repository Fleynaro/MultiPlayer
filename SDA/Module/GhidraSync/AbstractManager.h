#pragma once
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/protocol/TMultiplexedProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include "DataTypeManagerService.h"
#include "FunctionManagerService.h"

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

#include <Utils/ObjectHash.h>

namespace CE
{
	class ProgramModule;

	namespace Ghidra
	{
		using namespace ghidra;

		class DataTypeManager;
		class FunctionManager;

		class Client
		{
		public:
			friend class DataTypeManager;
			friend class FunctionManager;

			DataTypeManager* m_dataTypeManager = nullptr;
			FunctionManager* m_functionManager = nullptr;

			Client(ProgramModule* module)
				: m_module(module)
			{
				m_socket = std::shared_ptr<TTransport>(new TSocket("localhost", m_port));
				m_transport = std::shared_ptr<TTransport>(new TBufferedTransport(m_socket));
				m_protocol = std::shared_ptr<TProtocol>(new TBinaryProtocol(m_transport));
				initManagers();
			}

			void initManagers() {
				m_dataTypeManager = new DataTypeManager(getProgramModule()->getTypeManager(), this);
				m_functionManager = new FunctionManager(getProgramModule()->getFunctionManager(), this);
			}

			ProgramModule* getProgramModule() {
				return m_module;
			}
		private:
			ProgramModule* m_module = nullptr;

			std::shared_ptr<TTransport> m_socket;
			std::shared_ptr<TTransport> m_transport;
			std::shared_ptr<TProtocol> m_protocol;
			int m_port = 9090;
		};

		class AbstractManager
		{
		public:
			AbstractManager(Client* client)
				: m_client(client)
			{}
		protected:
			Client* getClient() {
				return m_client;
			}
		private:
			Client* m_client;
		};

		class Transport
		{
		public:
			Transport(std::shared_ptr<TTransport> transport)
				: m_transport(transport)
			{
				m_transport->open();
			}

			~Transport()
			{
				m_transport->close();
			}
		private:
			std::shared_ptr<TTransport> m_transport;
		};
	};
};