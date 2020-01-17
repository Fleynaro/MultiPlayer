#pragma once
#include <GhidraSync/FunctionManager.h>
#include "FunctionManager.h"

using namespace CE;

FunctionManager::FunctionManager(ProgramModule* module)
	: AbstractManager(module), m_ghidraManager(new Ghidra::FunctionManager(this, getProgramModule()->getGhidraClient()))
{
	createDefaultFunction();
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
