#include "FunctionDeclaration.h"

using namespace CE::Function;

FunctionDecl::FunctionDecl(int id, const std::string& name, const std::string& desc)
	: Desc(id, name, desc)
{}

std::string FunctionDecl::getSigName() {
	std::string name = getSignature().getReturnType()->getDisplayName() + " " + getName() + "(";

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

void FunctionDecl::addArgument(Type::Type* type, const std::string& name) {
	getSignature().addArgument(type);
	getArgNameList().push_back(name);
}

void FunctionDecl::changeArgument(int id, Type::Type* type, const std::string& name) {
	getSignature().changeArgument(id, type);
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
