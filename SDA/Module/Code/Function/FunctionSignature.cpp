#include "FunctionSignature.h"

using namespace CE;
using namespace CE::Function;

void Signature::setReturnType(DataTypePtr returnType) {
	m_returnType = returnType;
}

DataTypePtr Signature::getReturnType() {
	return m_returnType;
}

Signature::ArgTypeList& Signature::getArgList() {
	return m_args;
}

void Signature::addArgument(DataTypePtr type) {
	m_args.push_back(type);
}

void Signature::setArgument(int id, DataTypePtr type) {
	m_args[id] = type;
}

void Signature::removeLastArgument() {
	m_args.pop_back();
}

void Signature::deleteAllArguments() {
	m_args.clear();
}
