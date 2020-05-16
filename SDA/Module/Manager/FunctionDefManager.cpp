#include "FunctionDefManager.h"
#include <DB/Mappers/FunctionDefMapper.h>
#include <GhidraSync/Mappers/GhidraFunctionDefMapper.h>
#include <CodeGraph/FunctionBodyBuilder.h>
#include <CodeGraph/Analysis/GenericAnalysis.h>

using namespace CE;

FunctionManager::FunctionManager(ProgramModule* module, FunctionDeclManager* funcDeclManager)
	: AbstractItemManager(module), m_funcDeclManager(funcDeclManager)
{
	m_funcDefMapper = new DB::FunctionDefMapper(this);
	m_ghidraFunctionDefMapper = new Ghidra::FunctionDefMapper(this);
	createDefaultFunction();
}

FunctionManager::~FunctionManager() {
	delete m_funcDeclManager;
	delete m_ghidraFunctionDefMapper;
}

void FunctionManager::loadFunctions() {
	m_funcDeclManager->loadFunctionDecls();
	m_funcDefMapper->loadAll();
}

void FunctionManager::loadFunctionsFrom(Ghidra::DataPacket* dataPacket) {
	m_ghidraFunctionDefMapper->load(dataPacket);
}

Function::Function* FunctionManager::createFunction(ProcessModule* module, AddressRangeList ranges, CE::Function::FunctionDecl* decl) {
	auto def = new Function::Function(this, module, ranges, decl);
	def->setMapper(m_funcDefMapper);
	def->setGhidraMapper(m_ghidraFunctionDefMapper);
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
	return static_cast<Function::Function*>(find(id));
}

Function::Function* FunctionManager::getFunctionByGhidraId(Ghidra::Id id)
{
	Iterator it(this);
	while (it.hasNext()) {
		auto function = it.next();
		if (function->getGhidraId() == id) {
			return function;
		}
	}
	return nullptr;
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

