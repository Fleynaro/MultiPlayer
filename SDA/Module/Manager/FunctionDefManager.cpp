#include "FunctionDefManager.h"
#include <DB/Mappers/FunctionDefMapper.h>
#include <GhidraSync/FunctionManager.h>
#include <CodeGraph/FunctionBodyBuilder.h>
#include <CodeGraph/Analysis/GenericAnalysis.h>

using namespace CE;

FunctionManager::FunctionManager(ProgramModule* module, FunctionDeclManager* funcDeclManager)
	: AbstractItemManager(module), m_funcDeclManager(funcDeclManager)
{
	m_funcDefMapper = new DB::FunctionDefMapper(this);
	createDefaultFunction();
}

FunctionManager::~FunctionManager() {
	delete m_funcDeclManager;
}

void FunctionManager::loadFunctions() {
	m_funcDeclManager->loadFunctionDecls();
	m_funcDefMapper->loadAll();
}

Function::Function* FunctionManager::createFunction(void* addr, Function::AddressRangeList ranges, CE::Function::FunctionDecl* decl) {
	auto def = new Function::Function(this, addr, ranges, decl);
	def->setMapper(m_funcDefMapper);
	def->setId(m_funcDefMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(def);
	return def;
}

void FunctionManager::createDefaultFunction() {
	m_defFunction = new Function::Function(this, nullptr, {},
		new Function::FunctionDecl(getFunctionDeclManager(), "DefaultFunction", "This function created automatically."));
}

Function::Function* FunctionManager::getDefaultFunction() {
	return m_defFunction;
}

Function::Function* FunctionManager::getFunctionById(DB::Id id) {
	return (Function::Function*)find(id);
}

Function::Function* FunctionManager::getFunctionAt(void* addr) {
	Iterator it(this);
	while (it.hasNext()) {
		auto func = it.next();
		if (func->isContainingAddress(addr)) {
			return func;
		}
	}
	return nullptr;
}

FunctionDeclManager* FunctionManager::getFunctionDeclManager() {
	return m_funcDeclManager;
}

#include <Address/Address.h>
void FunctionManager::buildFunctionBodies() {
	Iterator it(this);
	while (it.hasNext()) {
		auto func = it.next();
		if (func->getBody()->getNodeList().size() > 0)
			continue;
		CodeGraph::FunctionBodyBuilder bodyBuilder(func->getBody(), func->getAddressRangeList(), this);
		if(Address(func->getAddress()).canBeRead())
			bodyBuilder.build();
	}
}

void FunctionManager::buildFunctionBasicInfo()
{
	CodeGraph::Analyser::GenericAll analyser(this);
	analyser.doAnalyse();
}

void FunctionManager::setFunctionTagManager(FunctionTagManager* manager) {
	m_tagManager = manager;
}

FunctionTagManager* FunctionManager::getFunctionTagManager() {
	return m_tagManager;
}

void FunctionManager::setGhidraManager(Ghidra::FunctionManager* ghidraManager) {
	m_ghidraManager = ghidraManager;
}

Ghidra::FunctionManager* FunctionManager::getGhidraManager() {
	return m_ghidraManager;
}

bool FunctionManager::isGhidraManagerWorking() {
	return getGhidraManager() != nullptr;
}