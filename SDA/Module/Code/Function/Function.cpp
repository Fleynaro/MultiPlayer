#include "Function.h"
#include "Module/Trigger/FunctionTrigger.h"
#include <Manager/FunctionManager.h>

using namespace CE;

Symbol::FunctionSymbol* Function::Function::getFunctionSymbol() {
	return m_functionSymbol;
}

ImageDecorator* CE::Function::Function::getImage() {
	return m_imageDec;
}

Decompiler::FunctionPCodeGraph* Function::Function::getFuncGraph() {
	return m_imageDec->getPCodeGraph()->getFuncGraphAt(getOffset());
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

int64_t CE::Function::Function::getOffset() {
	return m_functionSymbol->getOffset();
}

Symbol::SymbolTable* Function::Function::getStackSymbolTable() {
	return m_stackSymbolTable;
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

Ghidra::Id Function::Function::getGhidraId()
{
	return (Ghidra::Id)getOffset();
}

FunctionManager* Function::Function::getManager() {
	return m_manager;
}
