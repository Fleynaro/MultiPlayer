#pragma once
#include <GhidraSync/FunctionManager.h>
#include "FunctionManager.h"

using namespace CE;

FunctionManager::FunctionManager(ProgramModule* module)
	: AbstractManager(module)
{
	createDefaultFunction();
}

void CE::FunctionManager::buildFunctionBodies() {
	for (auto it : m_functions) {
		CallGraph::FunctionBodyBuilder bodyBuilder(it.second);
		bodyBuilder.build();
		it.second->getFunction()->setBody(bodyBuilder.getFunctionBody());
	}
}

void API::Function::Function::save() {
	lock();

	getFunctionManager()->saveFunction(getFunction());
	if (getFunctionManager()->isGhidraManagerWorking()) {
		getFunctionManager()->getGhidraManager()->push({
			getFunctionManager()->getGhidraManager()->buildDesc(getFunction())
			});
	}

	unlock();
}
