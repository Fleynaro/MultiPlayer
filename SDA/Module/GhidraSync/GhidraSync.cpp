#include "GhidraSync.h"

void CE::Ghidra::Client::initManagers() {
	m_dataTypeManager = new DataTypeManager(getSDA()->getTypeManager(), this);
	m_functionManager = new FunctionManager(getSDA()->getFunctionManager(), this);
}