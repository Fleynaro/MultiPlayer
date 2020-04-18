#include "FunctionDefinition.h"
#include "Module/Trigger/Trigger.h"

using namespace CE::Function;

int FunctionDefinition::getId() {
	return m_id;
}

void* FunctionDefinition::getAddress() {
	return m_addr;
}

AddressRangeList& FunctionDefinition::getRangeList() {
	return m_ranges;
}

void FunctionDefinition::addRange(AddressRange range) {
	m_ranges.push_back(range);
}

bool FunctionDefinition::isContainingAddress(void* addr) {
	for (auto& range : m_ranges) {
		if (range.isContainingAddress(addr)) {
			return true;
		}
	}
	return false;
}

CE::Trigger::Function::Hook* FunctionDefinition::getHook() {
	return m_hook;
}

bool FunctionDefinition::hasHook() {
	return m_hook != nullptr;
}

void FunctionDefinition::createHook() {
	m_hook = new CE::Trigger::Function::Hook(this);
}

FunctionDecl* FunctionDefinition::getDeclarationPtr() {
	return m_decl;
}

FunctionDecl& FunctionDefinition::getDeclaration() {
	return *getDeclarationPtr();
}
