#include "ConditionFilter.h"

using namespace CE::Trigger::Function::Filter;

ConditionFilter::ConditionFilter(Id id, std::list<AbstractFilter*> filters)
	: m_id(id), AbstractCompositeFilter(filters)
{
	switch (id)
	{
	case Id::Condition_AND:
		m_source = true;
		m_cmp = [](bool a, bool b) { return a & b; };
		break;
	case Id::Condition_OR:
		m_source = false;
		m_cmp = [](bool a, bool b) { return a | b; };
		break;
	case Id::Condition_XOR:
		m_source = false;
		m_cmp = [](bool a, bool b) { return a ^ b; };
		break;
	case Id::Condition_NOT:
		m_cmp = [](bool a, bool b) { return 1 ^ b; };
		break;
	}
}

Id ConditionFilter::getId() {
	return m_id;
}

bool ConditionFilter::checkFilterBefore(CE::Hook::DynHook* hook) {
	bool result = m_source;
	for (auto filter : m_filters) {
		result = m_cmp(result, filter->checkFilterBefore(hook));
	}
	return result;
}

bool ConditionFilter::checkFilterAfter(CE::Hook::DynHook* hook) {
	bool result = m_source;
	for (auto filter : m_filters) {
		result = m_cmp(result, filter->checkFilterAfter(hook));
	}
	return result;
}
