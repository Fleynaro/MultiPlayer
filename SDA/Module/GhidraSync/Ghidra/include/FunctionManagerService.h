/**
 * Autogenerated by Thrift Compiler (0.12.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef FunctionManagerService_H
#define FunctionManagerService_H

#include <thrift/TDispatchProcessor.h>
#include <thrift/async/TConcurrentClientSyncInfo.h>
#include "function_types.h"

namespace ghidra { namespace function {

#ifdef _MSC_VER
  #pragma warning( push )
  #pragma warning (disable : 4250 ) //inheriting methods via dominance 
#endif

class FunctionManagerServiceIf {
 public:
  virtual ~FunctionManagerServiceIf() {}
  virtual void pull(std::vector<SFunction> & _return, const HashMap& hashmap) = 0;
  virtual void push(const std::vector<SFunction> & functions) = 0;
};

class FunctionManagerServiceIfFactory {
 public:
  typedef FunctionManagerServiceIf Handler;

  virtual ~FunctionManagerServiceIfFactory() {}

  virtual FunctionManagerServiceIf* getHandler(const ::apache::thrift::TConnectionInfo& connInfo) = 0;
  virtual void releaseHandler(FunctionManagerServiceIf* /* handler */) = 0;
};

class FunctionManagerServiceIfSingletonFactory : virtual public FunctionManagerServiceIfFactory {
 public:
  FunctionManagerServiceIfSingletonFactory(const ::apache::thrift::stdcxx::shared_ptr<FunctionManagerServiceIf>& iface) : iface_(iface) {}
  virtual ~FunctionManagerServiceIfSingletonFactory() {}

  virtual FunctionManagerServiceIf* getHandler(const ::apache::thrift::TConnectionInfo&) {
    return iface_.get();
  }
  virtual void releaseHandler(FunctionManagerServiceIf* /* handler */) {}

 protected:
  ::apache::thrift::stdcxx::shared_ptr<FunctionManagerServiceIf> iface_;
};

class FunctionManagerServiceNull : virtual public FunctionManagerServiceIf {
 public:
  virtual ~FunctionManagerServiceNull() {}
  void pull(std::vector<SFunction> & /* _return */, const HashMap& /* hashmap */) {
    return;
  }
  void push(const std::vector<SFunction> & /* functions */) {
    return;
  }
};

typedef struct _FunctionManagerService_pull_args__isset {
  _FunctionManagerService_pull_args__isset() : hashmap(false) {}
  bool hashmap :1;
} _FunctionManagerService_pull_args__isset;

class FunctionManagerService_pull_args {
 public:

  FunctionManagerService_pull_args(const FunctionManagerService_pull_args&);
  FunctionManagerService_pull_args& operator=(const FunctionManagerService_pull_args&);
  FunctionManagerService_pull_args() {
  }

  virtual ~FunctionManagerService_pull_args() throw();
  HashMap hashmap;

  _FunctionManagerService_pull_args__isset __isset;

  void __set_hashmap(const HashMap& val);

  bool operator == (const FunctionManagerService_pull_args & rhs) const
  {
    if (!(hashmap == rhs.hashmap))
      return false;
    return true;
  }
  bool operator != (const FunctionManagerService_pull_args &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const FunctionManagerService_pull_args & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class FunctionManagerService_pull_pargs {
 public:


  virtual ~FunctionManagerService_pull_pargs() throw();
  const HashMap* hashmap;

  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};

typedef struct _FunctionManagerService_pull_result__isset {
  _FunctionManagerService_pull_result__isset() : success(false) {}
  bool success :1;
} _FunctionManagerService_pull_result__isset;

class FunctionManagerService_pull_result {
 public:

  FunctionManagerService_pull_result(const FunctionManagerService_pull_result&);
  FunctionManagerService_pull_result& operator=(const FunctionManagerService_pull_result&);
  FunctionManagerService_pull_result() {
  }

  virtual ~FunctionManagerService_pull_result() throw();
  std::vector<SFunction>  success;

  _FunctionManagerService_pull_result__isset __isset;

  void __set_success(const std::vector<SFunction> & val);

  bool operator == (const FunctionManagerService_pull_result & rhs) const
  {
    if (!(success == rhs.success))
      return false;
    return true;
  }
  bool operator != (const FunctionManagerService_pull_result &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const FunctionManagerService_pull_result & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};

typedef struct _FunctionManagerService_pull_presult__isset {
  _FunctionManagerService_pull_presult__isset() : success(false) {}
  bool success :1;
} _FunctionManagerService_pull_presult__isset;

class FunctionManagerService_pull_presult {
 public:


  virtual ~FunctionManagerService_pull_presult() throw();
  std::vector<SFunction> * success;

  _FunctionManagerService_pull_presult__isset __isset;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);

};

typedef struct _FunctionManagerService_push_args__isset {
  _FunctionManagerService_push_args__isset() : functions(false) {}
  bool functions :1;
} _FunctionManagerService_push_args__isset;

class FunctionManagerService_push_args {
 public:

  FunctionManagerService_push_args(const FunctionManagerService_push_args&);
  FunctionManagerService_push_args& operator=(const FunctionManagerService_push_args&);
  FunctionManagerService_push_args() {
  }

  virtual ~FunctionManagerService_push_args() throw();
  std::vector<SFunction>  functions;

  _FunctionManagerService_push_args__isset __isset;

  void __set_functions(const std::vector<SFunction> & val);

  bool operator == (const FunctionManagerService_push_args & rhs) const
  {
    if (!(functions == rhs.functions))
      return false;
    return true;
  }
  bool operator != (const FunctionManagerService_push_args &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const FunctionManagerService_push_args & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class FunctionManagerService_push_pargs {
 public:


  virtual ~FunctionManagerService_push_pargs() throw();
  const std::vector<SFunction> * functions;

  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class FunctionManagerService_push_result {
 public:

  FunctionManagerService_push_result(const FunctionManagerService_push_result&);
  FunctionManagerService_push_result& operator=(const FunctionManagerService_push_result&);
  FunctionManagerService_push_result() {
  }

  virtual ~FunctionManagerService_push_result() throw();

  bool operator == (const FunctionManagerService_push_result & /* rhs */) const
  {
    return true;
  }
  bool operator != (const FunctionManagerService_push_result &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const FunctionManagerService_push_result & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

};


class FunctionManagerService_push_presult {
 public:


  virtual ~FunctionManagerService_push_presult() throw();

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);

};

class FunctionManagerServiceClient : virtual public FunctionManagerServiceIf {
 public:
  FunctionManagerServiceClient(apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) {
    setProtocol(prot);
  }
  FunctionManagerServiceClient(apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) {
    setProtocol(iprot,oprot);
  }
 private:
  void setProtocol(apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) {
  setProtocol(prot,prot);
  }
  void setProtocol(apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) {
    piprot_=iprot;
    poprot_=oprot;
    iprot_ = iprot.get();
    oprot_ = oprot.get();
  }
 public:
  apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> getInputProtocol() {
    return piprot_;
  }
  apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> getOutputProtocol() {
    return poprot_;
  }
  void pull(std::vector<SFunction> & _return, const HashMap& hashmap);
  void send_pull(const HashMap& hashmap);
  void recv_pull(std::vector<SFunction> & _return);
  void push(const std::vector<SFunction> & functions);
  void send_push(const std::vector<SFunction> & functions);
  void recv_push();
 protected:
  apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> piprot_;
  apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> poprot_;
  ::apache::thrift::protocol::TProtocol* iprot_;
  ::apache::thrift::protocol::TProtocol* oprot_;
};

class FunctionManagerServiceProcessor : public ::apache::thrift::TDispatchProcessor {
 protected:
  ::apache::thrift::stdcxx::shared_ptr<FunctionManagerServiceIf> iface_;
  virtual bool dispatchCall(::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, const std::string& fname, int32_t seqid, void* callContext);
 private:
  typedef  void (FunctionManagerServiceProcessor::*ProcessFunction)(int32_t, ::apache::thrift::protocol::TProtocol*, ::apache::thrift::protocol::TProtocol*, void*);
  typedef std::map<std::string, ProcessFunction> ProcessMap;
  ProcessMap processMap_;
  void process_pull(int32_t seqid, ::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, void* callContext);
  void process_push(int32_t seqid, ::apache::thrift::protocol::TProtocol* iprot, ::apache::thrift::protocol::TProtocol* oprot, void* callContext);
 public:
  FunctionManagerServiceProcessor(::apache::thrift::stdcxx::shared_ptr<FunctionManagerServiceIf> iface) :
    iface_(iface) {
    processMap_["pull"] = &FunctionManagerServiceProcessor::process_pull;
    processMap_["push"] = &FunctionManagerServiceProcessor::process_push;
  }

  virtual ~FunctionManagerServiceProcessor() {}
};

class FunctionManagerServiceProcessorFactory : public ::apache::thrift::TProcessorFactory {
 public:
  FunctionManagerServiceProcessorFactory(const ::apache::thrift::stdcxx::shared_ptr< FunctionManagerServiceIfFactory >& handlerFactory) :
      handlerFactory_(handlerFactory) {}

  ::apache::thrift::stdcxx::shared_ptr< ::apache::thrift::TProcessor > getProcessor(const ::apache::thrift::TConnectionInfo& connInfo);

 protected:
  ::apache::thrift::stdcxx::shared_ptr< FunctionManagerServiceIfFactory > handlerFactory_;
};

class FunctionManagerServiceMultiface : virtual public FunctionManagerServiceIf {
 public:
  FunctionManagerServiceMultiface(std::vector<apache::thrift::stdcxx::shared_ptr<FunctionManagerServiceIf> >& ifaces) : ifaces_(ifaces) {
  }
  virtual ~FunctionManagerServiceMultiface() {}
 protected:
  std::vector<apache::thrift::stdcxx::shared_ptr<FunctionManagerServiceIf> > ifaces_;
  FunctionManagerServiceMultiface() {}
  void add(::apache::thrift::stdcxx::shared_ptr<FunctionManagerServiceIf> iface) {
    ifaces_.push_back(iface);
  }
 public:
  void pull(std::vector<SFunction> & _return, const HashMap& hashmap) {
    size_t sz = ifaces_.size();
    size_t i = 0;
    for (; i < (sz - 1); ++i) {
      ifaces_[i]->pull(_return, hashmap);
    }
    ifaces_[i]->pull(_return, hashmap);
    return;
  }

  void push(const std::vector<SFunction> & functions) {
    size_t sz = ifaces_.size();
    size_t i = 0;
    for (; i < (sz - 1); ++i) {
      ifaces_[i]->push(functions);
    }
    ifaces_[i]->push(functions);
  }

};

// The 'concurrent' client is a thread safe client that correctly handles
// out of order responses.  It is slower than the regular client, so should
// only be used when you need to share a connection among multiple threads
class FunctionManagerServiceConcurrentClient : virtual public FunctionManagerServiceIf {
 public:
  FunctionManagerServiceConcurrentClient(apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) {
    setProtocol(prot);
  }
  FunctionManagerServiceConcurrentClient(apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) {
    setProtocol(iprot,oprot);
  }
 private:
  void setProtocol(apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> prot) {
  setProtocol(prot,prot);
  }
  void setProtocol(apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> iprot, apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> oprot) {
    piprot_=iprot;
    poprot_=oprot;
    iprot_ = iprot.get();
    oprot_ = oprot.get();
  }
 public:
  apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> getInputProtocol() {
    return piprot_;
  }
  apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> getOutputProtocol() {
    return poprot_;
  }
  void pull(std::vector<SFunction> & _return, const HashMap& hashmap);
  int32_t send_pull(const HashMap& hashmap);
  void recv_pull(std::vector<SFunction> & _return, const int32_t seqid);
  void push(const std::vector<SFunction> & functions);
  int32_t send_push(const std::vector<SFunction> & functions);
  void recv_push(const int32_t seqid);
 protected:
  apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> piprot_;
  apache::thrift::stdcxx::shared_ptr< ::apache::thrift::protocol::TProtocol> poprot_;
  ::apache::thrift::protocol::TProtocol* iprot_;
  ::apache::thrift::protocol::TProtocol* oprot_;
  ::apache::thrift::async::TConcurrentClientSyncInfo sync_;
};

#ifdef _MSC_VER
  #pragma warning( pop )
#endif

}} // namespace

#endif
