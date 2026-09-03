#pragma once
#include "AbstractFilter.h"

namespace CE::Trigger::Function::Filter
{
	class AbstractCompositeFilter : public AbstractFilter
	{
	public:
		AbstractCompositeFilter(std::list<AbstractFilter*> filters = {});

		~AbstractCompositeFilter();

		void serialize(BitStream& bt) override;

		void deserialize(BitStream& bt) override;

		void addFilter(AbstractFilter* filter);

		void removeFilter(AbstractFilter* filter);

		std::list<AbstractFilter*>& getFilters();

		int m_filtersSavedCount = -1;
	protected:
		std::list<AbstractFilter*> m_filters;
	};
};