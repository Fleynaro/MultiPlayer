#include "ReturnValueArgumentFilter.h"

using namespace CE::Trigger::Function::Filter;
using namespace CE::Trigger::Function::Filter::Cmp;

RetValue::RetValue(uint64_t value, Operation operation)
	: m_value(value), m_operation(operation)
{}

Id RetValue::getId() {
	return Id::ReturnValue;
}

bool RetValue::checkFilterAfter(CE::Hook::DynHook* hook) {
	using namespace CE::DataType;

	auto function = (CE::Function::Function*)hook->getUserPtr();
	auto type = function->getSignature()->getReturnType();
	return cmp(
		GetReturnValue(type, hook),
		m_value,
		m_operation,
		type
	);
}

void RetValue::setOperation(Operation operation) {
	m_operation = operation;
}

void RetValue::serialize(BitStream& bt)
{
	Data data;
	data.m_value = m_value;
	data.m_operation = m_operation;
	bt.write(&data, sizeof(Data));
}

void RetValue::deserialize(BitStream& bt)
{
	Data data;
	bt.read(&data, sizeof(Data));
	m_value = data.m_value;
	m_operation = data.m_operation;
}
