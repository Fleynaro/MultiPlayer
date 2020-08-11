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
	m_funcDefMapper = new DB::FunctionMapper(this);
	m_ghidraFunctionMapper = new Ghidra::FunctionMapper(this, getProgramModule()->getTypeManager()->m_ghidraDataTypeMapper);
	createDefaultFunction();
}

FunctionManager::~FunctionManager() {
	delete m_ghidraFunctionMapper;
}

void FunctionManager::loadFunctions() {
	m_funcDefMapper->loadAll();
}

void FunctionManager::loadFunctionsFrom(ghidra::packet::SDataFullSyncPacket* dataPacket) {
	m_ghidraFunctionMapper->load(dataPacket);
}

Function::Function* FunctionManager::createFunction(Symbol::FunctionSymbol* functionSymbol, ProcessModule* module, AddressRangeList ranges, DataType::Signature* signature) {
	auto func = new Function::Function(this, functionSymbol, module, ranges, signature);
	func->setMapper(m_funcDefMapper);
	func->setGhidraMapper(m_ghidraFunctionMapper);
	func->setId(m_funcDefMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(func);
	return func;
}

Function::Function* FunctionManager::createFunction(const std::string& name, ProcessModule* module, AddressRangeList ranges, DataType::Signature* signature, const std::string& comment) {
	auto symbol = dynamic_cast<Symbol::FunctionSymbol*>(getProgramModule()->getSymbolManager()->createSymbol(Symbol::FUNCTION, DataType::GetUnit(signature), name, comment));
	auto func = createFunction(symbol, module, ranges, signature);
	if (auto memSymbol = dynamic_cast<Symbol::MemorySymbol*>(symbol)) {
		getProgramModule()->getGlobalMemoryArea()->addSymbol(memSymbol, module->toRelAddr(func->getAddress()));
	}
	return func;
}

void FunctionManager::createDefaultFunction() {
	auto sig = new DataType::Signature(getProgramModule()->getTypeManager(), "defSig");
	auto symbol = new Symbol::FunctionSymbol(getProgramModule()->getSymbolManager(), DataType::GetUnit(sig), "defFunction");
	m_defFunction = new Function::Function(this, symbol, nullptr, {}, sig);
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

