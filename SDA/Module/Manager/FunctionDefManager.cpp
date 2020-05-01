#include "FunctionDefManager.h"
#include <CallGraph/CallGraph.h>

using namespace CE;

FunctionDefManager::FunctionDefManager(ProgramModule* module, FunctionDeclManager* funcDeclManager)
	: AbstractItemManager(module), m_funcDeclManager(funcDeclManager)
{}

Function::Function* FunctionDefManager::createFunction(void* addr, Function::AddressRangeList ranges, CE::Function::FunctionDecl* decl) {
	auto def = new Function::Function(this, addr, ranges, decl);
	getProgramModule()->getTransaction()->markAsNew(def);
	return def;
}

void FunctionDefManager::createDefaultFunction() {
	m_defFunction = createFunction(nullptr, {}, getFunctionDeclManager()->createFunctionDecl("DefaultFunction", "This function created automatically."));
	m_items.insert(std::make_pair(0, m_defFunction));
}

Function::Function* FunctionDefManager::getDefaultFunction() {
	return m_defFunction;
}

Function::Function* FunctionDefManager::getFunctionById(DB::Id id) {
	return (Function::Function*)find(id);
}

Function::Function* FunctionDefManager::getFunctionAt(void* addr) {
	Iterator it(this);
	while (it.hasNext()) {
		auto func = it.next();
		if (func->isContainingAddress(addr)) {
			return func;
		}
	}
	return nullptr;
}

FunctionDeclManager* FunctionDefManager::getFunctionDeclManager() {
	return m_funcDeclManager;
}

void FunctionDefManager::buildFunctionBodies() {
	for (auto it : m_items) {
		auto func = (Function::Function*)it.second;
		if (func->getBody()->getNodeList().size() > 0)
			continue;
		CallGraph::FunctionBodyBuilder bodyBuilder(func);
		bodyBuilder.build();
	}
}

void FunctionDefManager::buildFunctionBasicInfo()
{
	CallGraph::Analyser::GenericAll analyser(this);
	analyser.doAnalyse();
}

void FunctionDefManager::setFunctionTagManager(Function::Tag::Manager* manager) {
	m_tagManager = manager;
}

Function::Tag::Manager* FunctionDefManager::getFunctionTagManager() {
	return m_tagManager;
}

void FunctionDefManager::setGhidraManager(Ghidra::FunctionManager* ghidraManager) {
	m_ghidraManager = ghidraManager;
}

Ghidra::FunctionManager* FunctionDefManager::getGhidraManager() {
	return m_ghidraManager;
}

bool FunctionDefManager::isGhidraManagerWorking() {
	return getGhidraManager() != nullptr;
}

FunctionDefManager::Iterator::Iterator(FunctionDefManager* manager)
	: m_iterator(manager->m_items.begin()), m_end(manager->m_items.end())
{}

bool FunctionDefManager::Iterator::hasNext() {
	return m_iterator != m_end;
}

Function::Function* FunctionDefManager::Iterator::next() {
	return static_cast<Function::Function*>((m_iterator++)->second);
}
