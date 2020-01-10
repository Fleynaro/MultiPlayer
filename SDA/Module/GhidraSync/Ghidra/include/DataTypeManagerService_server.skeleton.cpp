// This autogenerated skeleton file illustrates how to build a server.
// You should copy it to another filename to avoid overwriting it.

#include "DataTypeManagerService.h"
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;

using namespace  ::ghidra::datatype;

class DataTypeManagerServiceHandler : virtual public DataTypeManagerServiceIf {
 public:
  DataTypeManagerServiceHandler() {
    // Your initialization goes here
  }

  void pull(std::vector<SDataTypeBase> & _return) {
    // Your implementation goes here
    printf("pull\n");
  }

  void pullTypedefs(std::vector<SDataTypeTypedef> & _return, const HashMap& hashmap) {
    // Your implementation goes here
    printf("pullTypedefs\n");
  }

  void pullStructures(std::vector<SDataTypeStructure> & _return, const HashMap& hashmap) {
    // Your implementation goes here
    printf("pullStructures\n");
  }

  void pullEnums(std::vector<SDataTypeEnum> & _return, const HashMap& hashmap) {
    // Your implementation goes here
    printf("pullEnums\n");
  }

  void push(const std::vector<SDataType> & types) {
    // Your implementation goes here
    printf("push\n");
  }

  void pushTypedefs(const std::vector<SDataTypeTypedef> & typedefs) {
    // Your implementation goes here
    printf("pushTypedefs\n");
  }

  void pushStructures(const std::vector<SDataTypeStructure> & structures) {
    // Your implementation goes here
    printf("pushStructures\n");
  }

  void pushEnums(const std::vector<SDataTypeEnum> & enums) {
    // Your implementation goes here
    printf("pushEnums\n");
  }

};

int main(int argc, char **argv) {
  int port = 9090;
  ::apache::thrift::stdcxx::shared_ptr<DataTypeManagerServiceHandler> handler(new DataTypeManagerServiceHandler());
  ::apache::thrift::stdcxx::shared_ptr<TProcessor> processor(new DataTypeManagerServiceProcessor(handler));
  ::apache::thrift::stdcxx::shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
  ::apache::thrift::stdcxx::shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
  ::apache::thrift::stdcxx::shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());

  TSimpleServer server(processor, serverTransport, transportFactory, protocolFactory);
  server.serve();
  return 0;
}

