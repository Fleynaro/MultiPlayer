#include "AbstractCompositeFilter.h"

using namespace CE::Trigger::Function::Filter;

AbstractCompositeFilter::AbstractCompositeFilter(std::list<AbstractFilter*> filters)
	: m_filters(filters)
{}

AbstractCompositeFilter::~AbstractCompositeFilter() {
	for (auto filter : m_filters) {
		delete filter;
	}
}

void AbstractCompositeFilter::serialize(BitStream& bt)
{
	bt.write(static_cast<int>(m_filters.size()));
}

void AbstractCompositeFilter::deserialize(BitStream& bt)
{
	m_filtersSavedCount = bt.read<int>();
}

void AbstractCompositeFilter::addFilter(AbstractFilter* filter) {
	m_filters.push_back(filter);
}

void AbstractCompositeFilter::removeFilter(AbstractFilter* filter) {
	m_filters.remove(filter);
	delete filter;
}

std::list<AbstractFilter*>& AbstractCompositeFilter::getFilters() {
	return m_filters;
}
