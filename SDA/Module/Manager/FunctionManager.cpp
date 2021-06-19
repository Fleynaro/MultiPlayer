#include "FunctionManager.h"
#include "TypeManager.h"
#include "SymbolManager.h"
#include "SymbolTableManager.h"
#include <DB/Mappers/FunctionMapper.h>
#include <GhidraSync/Mappers/GhidraFunctionMapper.h>

using namespace CE;

FunctionManager::FunctionManager(Project* module)
	: AbstractItemManager(module)
{
	m_funcMapper = new DB::FunctionMapper(this);
	m_ghidraFunctionMapper = new Ghidra::FunctionMapper(this, getProject()->getTypeManager()->m_ghidraDataTypeMapper);
}

FunctionManager::~FunctionManager() {
	delete m_ghidraFunctionMapper;
}

FunctionManager::Factory FunctionManager::getFactory(bool generateId) {
	return Factory(this, m_ghidraFunctionMapper, m_funcMapper, generateId);
}

void FunctionManager::loadFunctions() {
	m_funcMapper->loadAll();
}

void FunctionManager::loadFunctionsFrom(ghidra::packet::SDataFullSyncPacket* dataPacket) {
	m_ghidraFunctionMapper->load(dataPacket);
}

Function::Function* CE::FunctionManager::findFunctionById(DB::Id id) {
	return dynamic_cast<Function::Function*>(find(id));
}

Function::Function* CE::FunctionManager::findFunctionByGhidraId(Ghidra::Id id)
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

Function::Function* CE::FunctionManager::Factory::createFunction(Symbol::FunctionSymbol* functionSymbol, ImageDecorator* imageDec, Symbol::SymbolTable* stackSymbolTable) {
	auto func = new Function::Function(m_functionManager, functionSymbol, imageDec, stackSymbolTable);
	func->setMapper(m_funcMapper);
	func->setGhidraMapper(m_ghidraFunctionMapper);
	if (m_generateId)
		func->setId(m_funcMapper->getNextId());
	return func;
}

Function::Function* CE::FunctionManager::Factory::createFunction(Symbol::FunctionSymbol* functionSymbol, ImageDecorator* imageDec) {
	auto factory = m_functionManager->getProject()->getSymTableManager()->getFactory();
	auto stackSymbolTable = factory.createSymbolTable(Symbol::SymbolTable::STACK_SPACE, 0x100000000);
	return createFunction(functionSymbol, imageDec, stackSymbolTable);
}

Function::Function* CE::FunctionManager::Factory::createFunction(int64_t offset, DataType::IFunctionSignature* funcSignature, ImageDecorator* imageDec, const std::string& name, const std::string& comment) {
	auto factory = m_functionManager->getProject()->getSymbolManager()->getFactory();
	auto functionSymbol = factory.createFunctionSymbol(offset, funcSignature, name, comment);
	imageDec->getGlobalSymbolTable()->addSymbol(functionSymbol, offset);
	return createFunction(functionSymbol, imageDec);
}
