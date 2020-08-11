#include "Function.h"
#include "Module/Trigger/FunctionTrigger.h"
#include <Manager/FunctionManager.h>
#include <Address/ProcessModule.h>

using namespace CE;

Function::Function(FunctionManager* manager, Symbol::FunctionSymbol* functionSymbol, ProcessModule* module, AddressRangeList ranges, DataType::Signature* signature)
	: m_manager(manager), m_functionSymbol(functionSymbol), m_module(module), m_ranges(ranges), m_signature(signature)
{}

Symbol::FunctionSymbol* Function::getFunctionSymbol() {
	return m_functionSymbol;
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

DataType::Signature* Function::getSignature() {
	return m_signature;
}

void* Function::getAddress() {
	return m_ranges.begin()->getMinAddress();
}

AddressRangeList& Function::getAddressRangeList() {
	return m_ranges;
}

void Function::addRange(AddressRange range) {
	m_ranges.push_back(range);
}

bool Function::isContainingAddress(void* addr) {
	for (auto& range : m_ranges) {
		if (range.isContainingAddress(addr)) {
			return true;
		}
	}
	return false;
}

Symbol::MemoryArea* Function::getStackMemoryArea() {
	return m_stackMemoryArea;
}

void Function::setStackMemoryArea(Symbol::MemoryArea* stackMemoryArea) {
	m_stackMemoryArea = stackMemoryArea;
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

bool Function::hasBody() {
	return m_funcBody != nullptr;
}

CodeGraph::Node::FunctionBody* Function::getBody() {
	if (m_funcBody == nullptr) {
		m_funcBody = new CodeGraph::Node::FunctionBody(this);
	}
	return m_funcBody;
}

void Function::setBody(CodeGraph::Node::FunctionBody* body) {
	if (m_funcBody != nullptr) {
		delete m_funcBody;
	}
	m_funcBody = body;
}

void Function::setExported(bool toggle) {
	m_exported = toggle;
}

bool Function::isExported() {
	return m_exported;
}

Ghidra::Id Function::getGhidraId()
{
	return (Ghidra::Id)getProcessModule()->toRelAddr(getAddress());
}

ProcessModule* Function::getProcessModule() {
	return m_module;
}

FunctionManager* Function::getManager() {
	return m_manager;
}
