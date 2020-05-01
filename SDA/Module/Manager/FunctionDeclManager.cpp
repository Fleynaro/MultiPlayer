#include "FunctionDeclManager.h"

using namespace CE;

FunctionDeclManager::FunctionDeclManager(ProgramModule* module)
	: AbstractItemManager(module)
{}

Function::FunctionDecl* FunctionDeclManager::createFunctionDecl(std::string name, std::string desc) {
	auto decl = new Function::FunctionDecl(this, name, desc);
	getProgramModule()->getTransaction()->markAsNew(decl);
	return decl;
}

Function::MethodDecl* FunctionDeclManager::createMethodDecl(std::string name, std::string desc) {
	auto decl = new Function::MethodDecl(this, name, desc);
	getProgramModule()->getTransaction()->markAsNew(decl);
	return decl;
}

Function::FunctionDecl* FunctionDeclManager::getFunctionDeclById(DB::Id id) {
	return (Function::FunctionDecl*)find(id);
}
