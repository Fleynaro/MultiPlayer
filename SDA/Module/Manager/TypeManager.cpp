#pragma once
#include <GhidraSync/DataTypeManager.h>
#include "TypeManager.h"

using namespace CE;

TypeManager::TypeManager(ProgramModule* module)
	: AbstractManager(module), m_ghidraManager(new Ghidra::DataTypeManager(this, getProgramModule()->getGhidraClient()))
{
	addSystemTypes();
	addGhidraSystemTypes();
}

void API::Type::Type::save() {
	lock();

	getTypeManager()->saveType(getType());
	if (getTypeManager()->isGhidraManagerWorking()) {
		pushToGhidra();
	}

	unlock();
}

void API::Type::Typedef::pushToGhidra() {
	getTypeManager()->getGhidraManager()->push({
		getTypeManager()->getGhidraManager()->buildDesc(getTypedef())
	});
}

void API::Type::Enum::pushToGhidra() {
	getTypeManager()->getGhidraManager()->push({
		getTypeManager()->getGhidraManager()->buildDesc(getEnum())
	});
}

void API::Type::Class::pushToGhidra() {
	getTypeManager()->getGhidraManager()->push({
		getTypeManager()->getGhidraManager()->buildDesc(getClass())
	});
}
