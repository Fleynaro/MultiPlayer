// This autogenerated skeleton file illustrates how to build a server.
// You should copy it to another filename to avoid overwriting it.

#include "FunctionManagerService.h"
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;

using namespace  ::ghidra::function;

class FunctionManagerServiceHandler : virtual public FunctionManagerServiceIf {
 public:
  FunctionManagerServiceHandler() {
    // Your initialization goes here
  }

  void pull(std::vector<SFunction> & _return, const HashMap& hashmap) {
    // Your implementation goes here
    printf("pull\n");
  }

  void push(const std::vector<SFunction> & functions) {
    // Your implementation goes here
    printf("push\n");
  }

};

int main(int argc, char **argv) {
  int port = 9090;
  ::apache::thrift::stdcxx::shared_ptr<FunctionManagerServiceHandler> handler(new FunctionManagerServiceHandler());
  ::apache::thrift::stdcxx::shared_ptr<TProcessor> processor(new FunctionManagerServiceProcessor(handler));
  ::apache::thrift::stdcxx::shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
  ::apache::thrift::stdcxx::shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
  ::apache::thrift::stdcxx::shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());

  TSimpleServer server(processor, serverTransport, transportFactory, protocolFactory);
  server.serve();
  return 0;
}

