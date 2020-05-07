#include "FunctionDeclManager.h"
#include "DB/Mappers/FunctionDeclMapper.h"

using namespace CE;

FunctionDeclManager::FunctionDeclManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_funcDeclMapper = new DB::FunctionDeclMapper(this);
}

void FunctionDeclManager::loadFunctionDecls() {
	m_funcDeclMapper->loadAll();
}

Function::FunctionDecl* FunctionDeclManager::createFunctionDecl(std::string name, std::string desc) {
	auto decl = new Function::FunctionDecl(this, name, desc);
	decl->setMapper(m_funcDeclMapper);
	decl->setId(m_funcDeclMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(decl);
	return decl;
}

Function::MethodDecl* FunctionDeclManager::createMethodDecl(std::string name, std::string desc) {
	auto decl = new Function::MethodDecl(this, name, desc);
	decl->setMapper(m_funcDeclMapper);
	decl->setId(m_funcDeclMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(decl);
	return decl;
}

Function::FunctionDecl* FunctionDeclManager::getFunctionDeclById(DB::Id id) {
	return (Function::FunctionDecl*)find(id);
}
