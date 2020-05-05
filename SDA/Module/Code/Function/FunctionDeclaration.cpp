#include "FunctionDeclaration.h"
#include <Manager/TypeManager.h>
#include <Manager/FunctionDeclManager.h>

using namespace CE;
using namespace CE::Function;

FunctionDecl::FunctionDecl(FunctionDeclManager* manager, const std::string& name, const std::string& desc)
	: m_manager(manager), m_desc(0, name, desc)
{
	getSignature().setReturnType(DataType::GetUnit(m_manager->getProgramModule()->getTypeManager()->getDefaultReturnType()));
}

Desc& FunctionDecl::getDesc() {
	return m_desc;
}

std::string FunctionDecl::getSigName() {
	std::string name = getSignature().getReturnType()->getDisplayName() + " " + m_desc.getName() + "(";

	auto& argList = getSignature().getArgList();
	for (int i = 0; i < argList.size(); i++) {
		name += argList[i]->getDisplayName() + " " + getArgNameList()[i] + ", ";
	}
	if (argList.size() > 0) {
		name.pop_back();
		name.pop_back();
	}
	return name + ")";
}

std::string FunctionDecl::getName() {
	return m_desc.getName();
}

Signature& FunctionDecl::getSignature() {
	return m_signature;
}

ArgNameList& FunctionDecl::getArgNameList() {
	return m_argNames;
}

FunctionDecl::Role FunctionDecl::getRole() {
	return Role::Function;
}

bool FunctionDecl::isFunction() {
	return isFunction(getRole());
}

bool FunctionDecl::isFunction(Role role) {
	return role == Role::Function;
}

FunctionDeclManager* FunctionDecl::getManager() {
	return m_manager;
}

void FunctionDecl::addArgument(DataTypePtr type, const std::string& name) {
	getSignature().addArgument(type);
	getArgNameList().push_back(name);
}

void FunctionDecl::changeArgument(int id, DataTypePtr type, const std::string& name) {
	getSignature().setArgument(id, type);
	if (name.length() > 0) {
		m_argNames[id] = name;
	}
}

void FunctionDecl::removeLastArgument() {
	getSignature().removeLastArgument();
	m_argNames.pop_back();
}

void FunctionDecl::deleteAllArguments() {
	getSignature().deleteAllArguments();
	getArgNameList().clear();
}
