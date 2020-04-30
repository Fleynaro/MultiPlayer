#pragma once
#include <GhidraSync/FunctionManager.h>
#include "FunctionManager.h"
#include <CallGraph/CallGraph.h>

using namespace CE;

FunctionManager::FunctionManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	createDefaultFunction();
}

void CE::FunctionManager::buildFunctionBodies() {
	for (auto it : m_functions) {
		if (it.second->getBody()->getNodeList().size() > 0)
			continue;
		CallGraph::FunctionBodyBuilder bodyBuilder(it.second);
		bodyBuilder.build();
	}
}

void CE::FunctionManager::buildFunctionBasicInfo()
{
	CallGraph::Analyser::GenericAll analyser(this);
	analyser.doAnalyse();
}

void API::Function::Function::save() {
	lock();

	getFunctionManager()->saveFunction(*getFunction());
	if (getFunctionManager()->isGhidraManagerWorking()) {
		getFunctionManager()->getGhidraManager()->push({
			getFunctionManager()->getGhidraManager()->buildDesc(getFunction())
			});
	}

	unlock();
}

CallGraph::Unit::FunctionBody* CE::API::Function::Function::getBody() {
	if (m_funcBody == nullptr) {
		m_funcBody = new CallGraph::Unit::FunctionBody(this);
	}
	return m_funcBody;
}

void CE::API::Function::Function::setBody(CallGraph::Unit::FunctionBody* body) {
	if (m_funcBody != nullptr) {
		delete m_funcBody;
	}
	m_funcBody = body;
}
