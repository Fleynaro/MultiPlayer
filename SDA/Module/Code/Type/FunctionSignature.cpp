#include "FunctionSignature.h"
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::DataType;

Signature::Signature(TypeManager* typeManager, const std::string& name, const std::string& comment)
	: UserType(typeManager, name, comment)
{
	setReturnType(DataType::GetUnit(typeManager->getProgramModule()->getTypeManager()->getDefaultReturnType()));
}

Type::Group Signature::getGroup() {
	return Group::Signature;
}

int Signature::getSize() {
	return sizeof(std::uintptr_t);
}

std::string Signature::getSigName() {
	std::string name = getReturnType()->getDisplayName() + " " + getName() + "(";

	auto& argList = getArguments();
	for (int i = 0; i < argList.size(); i++) {
		name += argList[i].second->getDisplayName() + " " + argList[i].first + ", ";
	}
	if (argList.size() > 0) {
		name.pop_back();
		name.pop_back();
	}
	return name + ")";
}

void Signature::setReturnType(DataTypePtr returnType) {
	m_returnType = returnType;
}

DataTypePtr Signature::getReturnType() {
	return m_returnType;
}

Signature::ArgList& Signature::getArguments() {
	return m_args;
}

void Signature::addArgument(const std::string& name, DataTypePtr type) {
	m_args.push_back(std::make_pair(name, type));
}

void Signature::setArgumentName(int idx, const std::string& name) {
	m_args[idx] = std::make_pair(name, m_args[idx].second);
}

void Signature::setArgumentType(int idx, DataTypePtr type) {
	m_args[idx] = std::make_pair(m_args[idx].first, type);
}

void Signature::removeLastArgument() {
	m_args.pop_back();
}

void Signature::deleteAllArguments() {
	m_args.clear();
}

