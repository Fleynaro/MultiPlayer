#include "FunctionTriggerMapper.h"
#include <Trigger/FunctionTrigger.h>

using namespace DB;
using namespace CE;

FunctionTriggerMapper::FunctionTriggerMapper(TriggerMapper* parentMapper)
	: ChildAbstractMapper(parentMapper)
{}

IDomainObject* FunctionTriggerMapper::doLoad(Database * db, SQLite::Statement & query) {
	auto trigger = new Trigger::Function::Trigger(
		query.getColumn("name"),
		query.getColumn("desc")
	);
	trigger->setId(query.getColumn("trigger_id"));
	loadFiltersForFuncTrigger(db, trigger);
	return trigger;
}

void FunctionTriggerMapper::doInsert(Database* db, IDomainObject* obj) {
	doUpdate(db, obj);
}

void FunctionTriggerMapper::doUpdate(Database* db, IDomainObject* obj) {
	auto tr = static_cast<Trigger::Function::Trigger*>(obj);
	saveFiltersForFuncTrigger(db, tr);
}

void FunctionTriggerMapper::doRemove(Database* db, IDomainObject* obj) {
	auto tr = static_cast<Trigger::Function::Trigger*>(obj);
	//tr->getFilters()->getFilters().clear();
	saveFiltersForFuncTrigger(db, tr);
}

void FunctionTriggerMapper::saveFiltersForFuncTrigger(Database* db, Trigger::Function::Trigger* trigger) {
	SQLite::Statement query(*db, "DELETE FROM sda_func_trigger_filters WHERE trigger_id=?1");
	query.bind(1, trigger->getId());
	query.exec();
	saveFiltersForFuncTriggerRec(db, trigger->getId(), 1, trigger->getFilters());
}

void FunctionTriggerMapper::saveFiltersForFuncTriggerRec(Database* db, DB::Id trigger_id, int filter_idx, Trigger::Function::Filter::AbstractFilter* filter) {
	using namespace Trigger::Function::Filter;

	if (filter_idx != 1) {
		BitStream bs;
		filter->serialize(bs);

		SQLite::Statement query(*db, "INSERT INTO sda_func_trigger_filters (trigger_id, filter_id, filter_idx, data) VALUES(?1, ?2, ?3, ?4)");
		query.bind(1, trigger_id);
		query.bind(2, (int)filter->getId());
		query.bind(3, filter_idx);
		query.bind(4, bs.getData(), bs.getSize());
		query.exec();
	}

	if (auto compositeFilter = dynamic_cast<AbstractCompositeFilter*>(filter)) {
		for (const auto& filter : compositeFilter->getFilters()) {
			saveFiltersForFuncTriggerRec(db, trigger_id, filter_idx + 1, filter);
		}
	}
}

void FunctionTriggerMapper::loadFiltersForFuncTrigger(Database* db, Trigger::Function::Trigger* trigger) {
	using namespace Trigger::Function::Filter;

	SQLite::Statement query(*db, "SELECT filter_id,data FROM sda_func_trigger_filters WHERE trigger_id=?1 ORDER BY filter_idx ASC");
	query.bind(1, trigger->getId());

	loadFiltersForFuncTriggerRec(query, trigger->getFilters());
}

void FunctionTriggerMapper::loadFiltersForFuncTriggerRec(SQLite::Statement& query, Trigger::Function::Filter::AbstractCompositeFilter* compositeFilter) {
	using namespace Trigger::Function::Filter;

	auto size = compositeFilter->m_filtersSavedCount != -1 ? compositeFilter->m_filtersSavedCount : 1000;
	for (int idx = 0; query.executeStep() && idx < size; idx++)
	{
		auto filter_id = (Trigger::Function::Filter::Id)(int)query.getColumn("filter_id");
		auto filterInfo = TriggerFilterInfo::Function::GetFilter(filter_id);
		auto filter = filterInfo->m_createFilter();

		BitStream bs;
		bs.write(query.getColumn("data").getBlob(), query.getColumn("data").getBytes());
		bs.resetPointer();
		filter->deserialize(bs);
		compositeFilter->addFilter(filter);

		if (auto compositeFilter_ = dynamic_cast<AbstractCompositeFilter*>(filter)) {
			loadFiltersForFuncTriggerRec(query, compositeFilter_);
		}
	}
}

TriggerMapper* FunctionTriggerMapper::getParentMapper() {
	return static_cast<TriggerMapper*>(m_parentMapper);
}

