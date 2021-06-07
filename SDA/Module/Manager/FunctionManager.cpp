#include "FunctionManager.h"
#include "MemoryAreaManager.h"
#include "TypeManager.h"
#include "SymbolManager.h"
#include <DB/Mappers/FunctionMapper.h>
#include <GhidraSync/Mappers/GhidraFunctionMapper.h>

using namespace CE;

FunctionManager::FunctionManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_funcMapper = new DB::FunctionMapper(this);
	m_ghidraFunctionMapper = new Ghidra::FunctionMapper(this, getProgramModule()->getTypeManager()->m_ghidraDataTypeMapper);
	createDefaultFunction();
}

FunctionManager::~FunctionManager() {
	delete m_ghidraFunctionMapper;
}

void FunctionManager::loadFunctions() {
	m_funcMapper->loadAll();
}

void FunctionManager::loadFunctionsFrom(ghidra::packet::SDataFullSyncPacket* dataPacket) {
	m_ghidraFunctionMapper->load(dataPacket);
}

void FunctionManager::bind(Function::Function* function) {
	function->setMapper(m_funcMapper);
	function->setId(m_funcMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(function);
}

void FunctionManager::createDefaultFunction() {
	auto sig = new DataType::Signature(getProgramModule()->getTypeManager(), "defSig");
	auto symbol = new Symbol::FunctionSymbol(DataType::GetUnit(sig), "defFunction");
	m_defFunction = new Function::Function(symbol, nullptr);
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

void FunctionManager::setFunctionTagManager(FunctionTagManager* manager) {
	m_tagManager = manager;
}

FunctionTagManager* FunctionManager::getFunctionTagManager() {
	return m_tagManager;
}

