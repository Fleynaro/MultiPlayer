#include "FunctionSignature.h"

using namespace CE;
using namespace CE::Function;

Signature::~Signature() {
	if (m_returnType != nullptr)
		m_returnType->free();
}

void Signature::setReturnType(DataType::Type* returnType) {
	if (m_returnType != nullptr)
		m_returnType->free();
	m_returnType = returnType;
	m_returnType->addOwner();
	//m_retTypeChanged = true;
}

CE::DataType::Type* Signature::getReturnType() {
	return m_returnType;
}

Signature::ArgTypeList& Signature::getArgList() {
	return m_args;
}

void Signature::addArgument(DataType::Type* type) {
	type->addOwner();
	m_args.push_back(type);
}

void Signature::changeArgument(int id, DataType::Type* type) {
	m_args[id]->free();
	type->addOwner();
	m_args[id] = type;
}

void Signature::removeLastArgument() {
	if (m_args.size() > 0)
		m_args[m_args.size() - 1]->free();
	m_args.pop_back();
}

void Signature::deleteAllArguments() {
	for (auto it : m_args) {
		it->free();
	}
	m_args.clear();
}
