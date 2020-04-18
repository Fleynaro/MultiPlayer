#pragma once
#include "AbstractCompositeFilter.h"

namespace CE::Trigger::Function::Filter
{
	class ConditionFilter : public AbstractCompositeFilter
	{
	public:
		ConditionFilter(Id id, std::list<AbstractFilter*> filters = {})
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

		Id getId() override {
			return m_id;
		}

		bool checkFilterBefore(CE::Hook::DynHook* hook) override {
			bool result = m_source;
			for (auto filter : m_filters) {
				result = m_cmp(result, filter->checkFilterBefore(hook));
			}
			return result;
		}

		bool checkFilterAfter(CE::Hook::DynHook* hook) override {
			bool result = m_source;
			for (auto filter : m_filters) {
				result = m_cmp(result, filter->checkFilterAfter(hook));
			}
			return result;
		}

	private:
		Id m_id;
		bool m_source;
		std::function<bool(bool, bool)> m_cmp;
	};
};