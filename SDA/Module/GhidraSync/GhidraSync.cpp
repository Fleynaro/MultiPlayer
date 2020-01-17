#include "GhidraSync.h"

void CE::Ghidra::Client::initManagers() {
	m_dataTypeManager = new DataTypeManager(getProgramModule()->getTypeManager(), this);
	m_functionManager = new FunctionManager(getProgramModule()->getFunctionManager(), this);
}