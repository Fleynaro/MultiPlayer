#pragma once
#include "AbstractFilter.h"

namespace CE::Trigger::Function::Filter
{
	class AbstractCompositeFilter : public AbstractFilter
	{
	public:
		AbstractCompositeFilter(std::list<AbstractFilter*> filters = {})
			: m_filters(filters)
		{}

		~AbstractCompositeFilter() {
			for (auto filter : m_filters) {
				delete filter;
			}
		}

		void serialize(BitStream& bt)
		{
			bt.write(static_cast<int>(m_filters.size()));
		}

		void deserialize(BitStream& bt)
		{
			m_filtersSavedCount = bt.read<int>();
		}

		void addFilter(AbstractFilter* filter) {
			m_filters.push_back(filter);
		}

		void removeFilter(AbstractFilter* filter) {
			m_filters.remove(filter);
			delete filter;
		}

		auto& getFilters() {
			return m_filters;
		}

		int m_filtersSavedCount = -1;
	protected:
		std::list<AbstractFilter*> m_filters;
	};
};