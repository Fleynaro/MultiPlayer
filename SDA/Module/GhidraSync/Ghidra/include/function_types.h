/**
 * Autogenerated by Thrift Compiler (0.12.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef function_TYPES_H
#define function_TYPES_H

#include <iosfwd>

#include <thrift/Thrift.h>
#include <thrift/TApplicationException.h>
#include <thrift/TBase.h>
#include <thrift/protocol/TProtocol.h>
#include <thrift/transport/TTransport.h>

#include <thrift/stdcxx.h>
#include "shared_types.h"


namespace ghidra { namespace function {

typedef int64_t Id;

class SFunctionRange;

class SFunctionSignature;

class SFunction;

typedef struct _SFunctionRange__isset {
  _SFunctionRange__isset() : minOffset(false), maxOffset(false) {}
  bool minOffset :1;
  bool maxOffset :1;
} _SFunctionRange__isset;

class SFunctionRange : public virtual ::apache::thrift::TBase {
 public:

  SFunctionRange(const SFunctionRange&);
  SFunctionRange& operator=(const SFunctionRange&);
  SFunctionRange() : minOffset(0), maxOffset(0) {
  }

  virtual ~SFunctionRange() throw();
  int32_t minOffset;
  int32_t maxOffset;

  _SFunctionRange__isset __isset;

  void __set_minOffset(const int32_t val);

  void __set_maxOffset(const int32_t val);

  bool operator == (const SFunctionRange & rhs) const
  {
    if (!(minOffset == rhs.minOffset))
      return false;
    if (!(maxOffset == rhs.maxOffset))
      return false;
    return true;
  }
  bool operator != (const SFunctionRange &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const SFunctionRange & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

  virtual void printTo(std::ostream& out) const;
};

void swap(SFunctionRange &a, SFunctionRange &b);

std::ostream& operator<<(std::ostream& out, const SFunctionRange& obj);

typedef struct _SFunctionSignature__isset {
  _SFunctionSignature__isset() : returnType(false), arguments(false) {}
  bool returnType :1;
  bool arguments :1;
} _SFunctionSignature__isset;

class SFunctionSignature : public virtual ::apache::thrift::TBase {
 public:

  SFunctionSignature(const SFunctionSignature&);
  SFunctionSignature& operator=(const SFunctionSignature&);
  SFunctionSignature() {
  }

  virtual ~SFunctionSignature() throw();
   ::ghidra::shared::STypeUnit returnType;
  std::vector< ::ghidra::shared::STypeUnit>  arguments;

  _SFunctionSignature__isset __isset;

  void __set_returnType(const  ::ghidra::shared::STypeUnit& val);

  void __set_arguments(const std::vector< ::ghidra::shared::STypeUnit> & val);

  bool operator == (const SFunctionSignature & rhs) const
  {
    if (!(returnType == rhs.returnType))
      return false;
    if (!(arguments == rhs.arguments))
      return false;
    return true;
  }
  bool operator != (const SFunctionSignature &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const SFunctionSignature & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

  virtual void printTo(std::ostream& out) const;
};

void swap(SFunctionSignature &a, SFunctionSignature &b);

std::ostream& operator<<(std::ostream& out, const SFunctionSignature& obj);

typedef struct _SFunction__isset {
  _SFunction__isset() : id(false), name(false), comment(false), argumentNames(false), signature(false), ranges(false) {}
  bool id :1;
  bool name :1;
  bool comment :1;
  bool argumentNames :1;
  bool signature :1;
  bool ranges :1;
} _SFunction__isset;

class SFunction : public virtual ::apache::thrift::TBase {
 public:

  SFunction(const SFunction&);
  SFunction& operator=(const SFunction&);
  SFunction() : id(0), name(), comment() {
  }

  virtual ~SFunction() throw();
  Id id;
  std::string name;
  std::string comment;
  std::vector<std::string>  argumentNames;
  SFunctionSignature signature;
  std::vector<SFunctionRange>  ranges;

  _SFunction__isset __isset;

  void __set_id(const Id val);

  void __set_name(const std::string& val);

  void __set_comment(const std::string& val);

  void __set_argumentNames(const std::vector<std::string> & val);

  void __set_signature(const SFunctionSignature& val);

  void __set_ranges(const std::vector<SFunctionRange> & val);

  bool operator == (const SFunction & rhs) const
  {
    if (!(id == rhs.id))
      return false;
    if (!(name == rhs.name))
      return false;
    if (!(comment == rhs.comment))
      return false;
    if (!(argumentNames == rhs.argumentNames))
      return false;
    if (!(signature == rhs.signature))
      return false;
    if (!(ranges == rhs.ranges))
      return false;
    return true;
  }
  bool operator != (const SFunction &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const SFunction & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

  virtual void printTo(std::ostream& out) const;
};

void swap(SFunction &a, SFunction &b);

std::ostream& operator<<(std::ostream& out, const SFunction& obj);

}} // namespace

#endif
