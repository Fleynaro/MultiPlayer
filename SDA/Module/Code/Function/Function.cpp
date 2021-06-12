#include "Function.h"
#include "Module/Trigger/FunctionTrigger.h"
#include <Manager/FunctionManager.h>
#include <Address/ProcessModule.h>

using namespace CE;

Symbol::FunctionSymbol* Function::Function::getFunctionSymbol() {
	return m_functionSymbol;
}

Decompiler::FunctionPCodeGraph* Function::Function::getFuncGraph() {
	return m_funcGraph;
}

const std::string Function::Function::getName() {
	return m_functionSymbol->getName();
}

const std::string Function::Function::getComment() {
	return m_functionSymbol->getComment();
}

void Function::Function::setName(const std::string& name) {
	m_functionSymbol->setName(name);
}

void Function::Function::setComment(const std::string& comment) {
	m_functionSymbol->setComment(comment);
}

DataType::IFunctionSignature* Function::Function::getSignature() {
	return m_functionSymbol->getSignature();
}

int Function::Function::getOffset() {
	return m_functionSymbol->getOffset();
}

Symbol::SymbolTable* Function::Function::getStackMemoryArea() {
	return m_stackSymbolTable;
}

void Function::Function::setStackMemoryArea(Symbol::SymbolTable* stackMemoryArea) {
	m_stackSymbolTable = stackMemoryArea;
}

Symbol::SymbolTable* Function::Function::getBodyMemoryArea() {
	return m_bodyMemoryArea;
}

void Function::Function::setBodyMemoryArea(Symbol::SymbolTable* bodyMemoryArea) {
	m_bodyMemoryArea = bodyMemoryArea;
}

CE::Trigger::Function::Hook* Function::Function::getHook() {
	return m_hook;
}

bool Function::Function::hasHook() {
	return m_hook != nullptr;
}

void Function::Function::createHook() {
	m_hook = new CE::Trigger::Function::Hook(this);
}

void Function::Function::setExported(bool toggle) {
	m_exported = toggle;
}

bool Function::Function::isExported() {
	return m_exported;
}

Ghidra::Id Function::Function::getGhidraId()
{
	return (Ghidra::Id)getOffset();
}

ProcessModule* Function::Function::getProcessModule() {
	return m_processModule;
}

FunctionManager* Function::Function::getManager() {
	return m_manager;
}
