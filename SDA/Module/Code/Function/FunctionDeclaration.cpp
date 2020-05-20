#include "FunctionDeclaration.h"
#include <Manager/FunctionDeclManager.h>

using namespace CE;
using namespace CE::Function;

FunctionDecl::FunctionDecl(FunctionDeclManager* manager, DataType::Signature* signature, const std::string& name, const std::string& desc)
	: m_manager(manager), m_signature(signature), Descrtiption(name, desc)
{}

DataType::Signature* FunctionDecl::getSignature() {
	return m_signature;
}

FunctionDecl::Role FunctionDecl::getRole() {
	return Role::Function;
}

bool FunctionDecl::isFunction() {
	return isFunction(getRole());
}

std::list<FunctionDefinition*>& FunctionDecl::getFunctions() {
	return m_functions;
}

bool FunctionDecl::isFunction(Role role) {
	return role == Role::Function;
}

void FunctionDecl::setExported(bool toggle) {
	m_exported = toggle;
}

bool FunctionDecl::isExported() {
	return m_exported;
}

FunctionDeclManager* FunctionDecl::getManager() {
	return m_manager;
}

