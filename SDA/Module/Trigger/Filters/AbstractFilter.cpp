#include "AbstractFilter.h"

using namespace CE::Trigger::Function::Filter;

bool AbstractFilter::checkFilterBefore(CE::Hook::DynHook* hook) {
	return m_beforeDefFilter;
}

bool AbstractFilter::checkFilterAfter(CE::Hook::DynHook* hook) {
	return m_afterDefFilter;
}

void AbstractFilter::setBeforeDefaultFilter(bool toggle) {
	m_beforeDefFilter = toggle;
}

void AbstractFilter::setAfterDefaultFilter(bool toggle) {
	m_afterDefFilter = toggle;
}

uint64_t CE::Trigger::Function::GetArgumentValue(CE::DataTypePtr type, CE::Hook::DynHook* hook, int argIdx) {
	using namespace CE::DataType;
	if (argIdx <= 4 && type->isFloatingPoint())
		return hook->getXmmArgumentValue(argIdx);
	return hook->getArgumentValue(argIdx);
}

uint64_t CE::Trigger::Function::GetReturnValue(CE::DataTypePtr type, CE::Hook::DynHook* hook) {
	using namespace CE::DataType;
	if (type->isFloatingPoint())
		return hook->getXmmReturnValue();
	return hook->getReturnValue();
}