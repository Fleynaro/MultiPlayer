/**
 * Autogenerated by Thrift Compiler (0.12.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#include "variable_types.h"

#include <algorithm>
#include <ostream>

#include <thrift/TToString.h>

namespace ghidra { namespace variable {


SGlobalVar::~SGlobalVar() throw() {
}


void SGlobalVar::__set_id(const Id val) {
  this->id = val;
}

void SGlobalVar::__set_name(const std::string& val) {
  this->name = val;
}

void SGlobalVar::__set_comment(const std::string& val) {
  this->comment = val;
}

void SGlobalVar::__set_type(const  ::ghidra::shared::STypeUnit& val) {
  this->type = val;
}
std::ostream& operator<<(std::ostream& out, const SGlobalVar& obj)
{
  obj.printTo(out);
  return out;
}


uint32_t SGlobalVar::read(::apache::thrift::protocol::TProtocol* iprot) {

  ::apache::thrift::protocol::TInputRecursionTracker tracker(*iprot);
  uint32_t xfer = 0;
  std::string fname;
  ::apache::thrift::protocol::TType ftype;
  int16_t fid;

  xfer += iprot->readStructBegin(fname);

  using ::apache::thrift::protocol::TProtocolException;


  while (true)
  {
    xfer += iprot->readFieldBegin(fname, ftype, fid);
    if (ftype == ::apache::thrift::protocol::T_STOP) {
      break;
    }
    switch (fid)
    {
      case 1:
        if (ftype == ::apache::thrift::protocol::T_I64) {
          xfer += iprot->readI64(this->id);
          this->__isset.id = true;
        } else {
          xfer += iprot->skip(ftype);
        }
        break;
      case 2:
        if (ftype == ::apache::thrift::protocol::T_STRING) {
          xfer += iprot->readString(this->name);
          this->__isset.name = true;
        } else {
          xfer += iprot->skip(ftype);
        }
        break;
      case 3:
        if (ftype == ::apache::thrift::protocol::T_STRING) {
          xfer += iprot->readString(this->comment);
          this->__isset.comment = true;
        } else {
          xfer += iprot->skip(ftype);
        }
        break;
      case 4:
        if (ftype == ::apache::thrift::protocol::T_STRUCT) {
          xfer += this->type.read(iprot);
          this->__isset.type = true;
        } else {
          xfer += iprot->skip(ftype);
        }
        break;
      default:
        xfer += iprot->skip(ftype);
        break;
    }
    xfer += iprot->readFieldEnd();
  }

  xfer += iprot->readStructEnd();

  return xfer;
}

uint32_t SGlobalVar::write(::apache::thrift::protocol::TProtocol* oprot) const {
  uint32_t xfer = 0;
  ::apache::thrift::protocol::TOutputRecursionTracker tracker(*oprot);
  xfer += oprot->writeStructBegin("SGlobalVar");

  xfer += oprot->writeFieldBegin("id", ::apache::thrift::protocol::T_I64, 1);
  xfer += oprot->writeI64(this->id);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin("name", ::apache::thrift::protocol::T_STRING, 2);
  xfer += oprot->writeString(this->name);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin("comment", ::apache::thrift::protocol::T_STRING, 3);
  xfer += oprot->writeString(this->comment);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin("type", ::apache::thrift::protocol::T_STRUCT, 4);
  xfer += this->type.write(oprot);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldStop();
  xfer += oprot->writeStructEnd();
  return xfer;
}

void swap(SGlobalVar &a, SGlobalVar &b) {
  using ::std::swap;
  swap(a.id, b.id);
  swap(a.name, b.name);
  swap(a.comment, b.comment);
  swap(a.type, b.type);
  swap(a.__isset, b.__isset);
}

SGlobalVar::SGlobalVar(const SGlobalVar& other0) {
  id = other0.id;
  name = other0.name;
  comment = other0.comment;
  type = other0.type;
  __isset = other0.__isset;
}
SGlobalVar& SGlobalVar::operator=(const SGlobalVar& other1) {
  id = other1.id;
  name = other1.name;
  comment = other1.comment;
  type = other1.type;
  __isset = other1.__isset;
  return *this;
}
void SGlobalVar::printTo(std::ostream& out) const {
  using ::apache::thrift::to_string;
  out << "SGlobalVar(";
  out << "id=" << to_string(id);
  out << ", " << "name=" << to_string(name);
  out << ", " << "comment=" << to_string(comment);
  out << ", " << "type=" << to_string(type);
  out << ")";
}

}} // namespace
