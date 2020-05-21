#include "GlobalVar.h"
#include <Address/ProcessModule.h>
#include "GlobalVar.h"

using namespace CE;
using namespace CE::Variable;

GlobalVar::GlobalVar(GlobalVarManager* manager, ProcessModule* module, void* addr, const std::string& name, const std::string& comment)
	: m_manager(manager), m_module(module), m_addr(addr), Descrtiption(name, comment)
{}

Ghidra::Id GlobalVar::getGhidraId()
{
	return (Ghidra::Id)getProcessModule()->toRelAddr(getAddress());
}

ProcessModule* GlobalVar::getProcessModule() {
	return m_module;
}

void* GlobalVar::getAddress() {
	return m_addr;
}

DataTypePtr GlobalVar::getType() {
	return m_type;
}

void GlobalVar::setType(DataTypePtr type) {
	m_type = type;
}

GlobalVarManager* GlobalVar::getManager() {
	return m_manager;
}
