#include "ArgumentCmpFilter.h"

using namespace CE::Trigger::Function::Filter;
using namespace CE::Trigger::Function::Filter::Cmp;

Argument::Argument(int argId, uint64_t value, Operation operation)
	: m_argId(argId), m_value(value), m_operation(operation)
{}

Id Argument::getId() {
	return Id::Argument;
}

bool Argument::checkFilterBefore(CE::Hook::DynHook* hook) {
	using namespace CE::DataType;

	auto function = (CE::Function::FunctionDefinition*)hook->getUserPtr();
	auto& argList = function->getDeclaration().getSignature()->getParameters();
	if (m_argId > argList.size())
		return false;

	auto type = argList[m_argId - 1]->getDataType();
	return cmp(
		GetArgumentValue(type, hook, m_argId),
		m_value,
		m_operation,
		type
	);
}

void Argument::setOperation(Operation operation) {
	m_operation = operation;
}

void Argument::serialize(BitStream& bt)
{
	Data data;
	data.m_argId = m_argId;
	data.m_value = m_value;
	data.m_operation = m_operation;
	bt.write(&data, sizeof(Data));
}

void Argument::deserialize(BitStream& bt)
{
	Data data;
	bt.read(&data, sizeof(Data));
	m_argId = data.m_argId;
	m_value = data.m_value;
	m_operation = data.m_operation;
}
