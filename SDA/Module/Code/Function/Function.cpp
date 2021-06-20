#include "Function.h"
#include "Module/Trigger/FunctionTrigger.h"
#include <Manager/FunctionManager.h>

using namespace CE;

Symbol::FunctionSymbol* Function::getFunctionSymbol() {
	return m_functionSymbol;
}

ImageDecorator* CE::Function::getImage() {
	return m_imageDec;
}

Decompiler::FunctionPCodeGraph* Function::getFuncGraph() {
	return m_imageDec->getPCodeGraph()->getFuncGraphAt(getOffset());
}

const std::string Function::getName() {
	return m_functionSymbol->getName();
}

const std::string Function::getComment() {
	return m_functionSymbol->getComment();
}

void Function::setName(const std::string& name) {
	m_functionSymbol->setName(name);
}

void Function::setComment(const std::string& comment) {
	m_functionSymbol->setComment(comment);
}

DataType::IFunctionSignature* Function::getSignature() {
	return m_functionSymbol->getSignature();
}

int64_t CE::Function::getOffset() {
	return m_functionSymbol->getOffset();
}

Symbol::SymbolTable* Function::getStackSymbolTable() {
	return m_stackSymbolTable;
}

CE::Trigger::Function::Hook* Function::getHook() {
	return m_hook;
}

bool Function::hasHook() {
	return m_hook != nullptr;
}

void Function::createHook() {
	m_hook = new CE::Trigger::Function::Hook(this);
}

Ghidra::Id Function::getGhidraId()
{
	return (Ghidra::Id)getOffset();
}

FunctionManager* Function::getManager() {
	return m_manager;
}
