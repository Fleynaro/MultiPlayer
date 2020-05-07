#pragma once
#include "AbstractCompositeFilter.h"

namespace CE::Trigger::Function::Filter
{
	class ConditionFilter : public AbstractCompositeFilter
	{
	public:
		ConditionFilter(Id id, std::list<AbstractFilter*> filters = {});

		Id getId() override;

		bool checkFilterBefore(CE::Hook::DynHook* hook) override;

		bool checkFilterAfter(CE::Hook::DynHook* hook) override;

	private:
		Id m_id;
		bool m_source;
		std::function<bool(bool, bool)> m_cmp;
	};
};