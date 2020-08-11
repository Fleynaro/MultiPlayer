#include "Function.h"
#include "Module/Trigger/FunctionTrigger.h"
#include <Manager/FunctionManager.h>
#include <Address/ProcessModule.h>

using namespace CE;

Function::Function::Function(FunctionManager* manager, Symbol::FunctionSymbol* functionSymbol, ProcessModule* module, AddressRangeList ranges, DataType::Signature* signature)
	: m_manager(manager), m_functionSymbol(functionSymbol), m_module(module), m_ranges(ranges), m_signature(signature)
{}

Symbol::FunctionSymbol* Function::Function::getFunctionSymbol() {
	return m_functionSymbol;
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

DataType::Signature* Function::Function::getSignature() {
	return m_signature;
}

void* Function::Function::getAddress() {
	return m_ranges.begin()->getMinAddress();
}

AddressRangeList& Function::Function::getAddressRangeList() {
	return m_ranges;
}

void Function::Function::addRange(AddressRange range) {
	m_ranges.push_back(range);
}

bool Function::Function::isContainingAddress(void* addr) {
	for (auto& range : m_ranges) {
		if (range.isContainingAddress(addr)) {
			return true;
		}
	}
	return false;
}

Symbol::MemoryArea* Function::Function::getStackMemoryArea() {
	return m_stackMemoryArea;
}

void Function::Function::setStackMemoryArea(Symbol::MemoryArea* stackMemoryArea) {
	m_stackMemoryArea = stackMemoryArea;
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
	return (Ghidra::Id)getProcessModule()->toRelAddr(getAddress());
}

ProcessModule* Function::Function::getProcessModule() {
	return m_module;
}

FunctionManager* Function::Function::getManager() {
	return m_manager;
}
