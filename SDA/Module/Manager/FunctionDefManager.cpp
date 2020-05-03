#include "FunctionDefManager.h"
#include <DB/Mappers/FunctionDefMapper.h>
#include <GhidraSync/FunctionManager.h>
#include <CallGraph/CallGraph.h>

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
	def->getSignature().setReturnType(getProgramModule()->getTypeManager()->getDefaultReturnType());
	def->setMapper(m_funcDefMapper);
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

void FunctionManager::buildFunctionBodies() {
	for (auto it : m_items) {
		auto func = (Function::Function*)it.second;
		if (func->getBody()->getNodeList().size() > 0)
			continue;
		CallGraph::FunctionBodyBuilder bodyBuilder(func);
		bodyBuilder.build();
	}
}

void FunctionManager::buildFunctionBasicInfo()
{
	CallGraph::Analyser::GenericAll analyser(this);
	analyser.doAnalyse();
}

void FunctionManager::setFunctionTagManager(Function::Tag::Manager* manager) {
	m_tagManager = manager;
}

Function::Tag::Manager* FunctionManager::getFunctionTagManager() {
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

//FunctionManager::Iterator::Iterator(FunctionManager* manager)
//	: m_iterator(manager->m_items.begin()), m_end(manager->m_items.end())
//{}
//
//bool FunctionManager::Iterator::hasNext() {
//	return m_iterator != m_end;
//}
//
//Function::Function* FunctionManager::Iterator::next() {
//	return static_cast<Function::Function*>((m_iterator++)->second);
//}
