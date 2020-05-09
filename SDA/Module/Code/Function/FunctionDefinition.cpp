#include "FunctionDefinition.h"
#include "Module/Trigger/FunctionTrigger.h"
#include <CodeGraph/Nodes/BodyNode.h>
#include <Manager/FunctionDefManager.h>

using namespace CE;
using namespace CE::Function;

FunctionDefinition::FunctionDefinition(FunctionManager* manager, void* addr, AddressRangeList ranges, FunctionDecl* decl)
	: m_manager(manager), m_addr(addr), m_ranges(ranges), m_decl(decl)
{
	decl->getFunctions().push_back(this);
}

std::string CE::Function::FunctionDefinition::getName() {
	return getDeclaration().getDesc().getName();
}

std::string CE::Function::FunctionDefinition::getComment() {
	return getDeclaration().getDesc().getDesc();
}

std::string CE::Function::FunctionDefinition::getSigName() {
	return getDeclaration().getSigName();
}

bool CE::Function::FunctionDefinition::isFunction() {
	return getDeclaration().isFunction();
}

Signature& CE::Function::FunctionDefinition::getSignature() {
	return getDeclaration().getSignature();
}

ArgNameList& CE::Function::FunctionDefinition::getArgNameList() {
	return getDeclaration().getArgNameList();
}

void* FunctionDefinition::getAddress() {
	return m_addr;
}

int FunctionDefinition::getOffset() {
	return getManager()->getProgramModule()->toRelAddr(getAddress());
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

bool FunctionDefinition::hasBody() {
	return m_funcBody != nullptr;
}

CallGraph::Node::FunctionBody* FunctionDefinition::getBody() {
	if (m_funcBody == nullptr) {
		m_funcBody = new CallGraph::Node::FunctionBody(this);
	}
	return m_funcBody;
}

void FunctionDefinition::setBody(CallGraph::Node::FunctionBody* body) {
	if (m_funcBody != nullptr) {
		delete m_funcBody;
	}
	m_funcBody = body;
}

bool FunctionDefinition::isGhidraUnit() {
	return m_ghidraUnit;
}

void FunctionDefinition::setGhidraUnit(bool toggle) {
	m_ghidraUnit = toggle;
}

FunctionManager* FunctionDefinition::getManager() {
	return m_manager;
}
