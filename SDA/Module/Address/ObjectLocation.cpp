#include "ObjectLocation.h"
#include "ProcessModule.h"

using namespace CE;

int ObjectLocation::getOffset() {
	return m_offset;
}

ProccessModule* ObjectLocation::getProccessModule() {
	return m_module;
}

void* ObjectLocation::getAddress() {
	return (void*)(m_module->getBaseAddr() + m_offset);
}

ObjectLocation::ObjectLocation(ProccessModule* module, int offset)
	: m_module(module), m_offset(offset)
{}
