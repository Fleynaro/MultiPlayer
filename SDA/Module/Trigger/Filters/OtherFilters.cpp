#include "OtherFilters.h"

using namespace CE::Trigger::Function::Filter;

Id Empty::getId() {
	return Id::Empty;
}

bool Empty::checkFilterBefore(CE::Hook::DynHook* hook) {
	return true;
}

bool Empty::checkFilterAfter(CE::Hook::DynHook* hook) {
	return true;
}


Object::Object(void* addr)
	: m_addr(addr)
{}

Id Object::getId() {
	return Id::Object;
}

bool Object::checkFilterBefore(CE::Hook::DynHook* hook) {
	return hook->getArgumentValue<void*>(1) == m_addr;
}

void Object::serialize(BitStream& bt)
{
	Data data;
	data.m_addr = m_addr;
	bt.write(&data, sizeof(Data));
}

void Object::deserialize(BitStream& bt)
{
	Data data;
	bt.read(&data, sizeof(Data));
	m_addr = data.m_addr;
}