#include "FunctionDefinition.h"
#include "Module/Trigger/FunctionTrigger.h"
#include <CodeGraph/Nodes/BodyNode.h>
#include <Manager/FunctionDefManager.h>
#include <Address/ProcessModule.h>

using namespace CE;
using namespace CE::Function;

FunctionDefinition::FunctionDefinition(FunctionManager* manager, ProcessModule* module, AddressRangeList ranges, FunctionDecl* decl)
	: m_manager(manager), m_module(module), m_ranges(ranges), m_decl(decl)
{
	decl->getFunctions().push_back(this);
}

const std::string FunctionDefinition::getName() {
	return getDeclaration().getName();
}

const std::string FunctionDefinition::getComment() {
	return getDeclaration().getComment();
}

void FunctionDefinition::setName(const std::string& name) {
	getDeclaration().setName(name);
}

void FunctionDefinition::setComment(const std::string& comment) {
	getDeclaration().setComment(comment);
}

std::string FunctionDefinition::getSigName() {
	return getDeclaration().getSigName();
}

bool FunctionDefinition::isFunction() {
	return getDeclaration().isFunction();
}

Signature& FunctionDefinition::getSignature() {
	return getDeclaration().getSignature();
}

ArgNameList& FunctionDefinition::getArgNameList() {
	return getDeclaration().getArgNameList();
}

void* FunctionDefinition::getAddress() {
	return m_ranges.begin()->getMinAddress();
}

AddressRangeList& FunctionDefinition::getAddressRangeList() {
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

CodeGraph::Node::FunctionBody* FunctionDefinition::getBody() {
	if (m_funcBody == nullptr) {
		m_funcBody = new CodeGraph::Node::FunctionBody(this);
	}
	return m_funcBody;
}

void FunctionDefinition::setBody(CodeGraph::Node::FunctionBody* body) {
	if (m_funcBody != nullptr) {
		delete m_funcBody;
	}
	m_funcBody = body;
}

void FunctionDefinition::setExported(bool toggle) {
	getDeclaration().setExported(toggle);
}

bool FunctionDefinition::isExported() {
	return getDeclaration().isExported();
}

Ghidra::Id FunctionDefinition::getGhidraId()
{
	return (Ghidra::Id)getProcessModule()->toRelAddr(getAddress());
}

ProcessModule* FunctionDefinition::getProcessModule() {
	return m_module;
}

FunctionManager* FunctionDefinition::getManager() {
	return m_manager;
}
