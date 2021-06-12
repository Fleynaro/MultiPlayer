#include "TriggerGroupManager.h"
#include <DB/Mappers/TriggerGroupMapper.h>

using namespace CE;

TriggerGroupManager::TriggerGroupManager(Project* module)
	: AbstractItemManager(module)
{
	m_triggerGroupMapper = new DB::TriggerGroupMapper(this);
}

void TriggerGroupManager::loadTriggerGroups()
{
	m_triggerGroupMapper->loadAll();
}

Trigger::TriggerGroup* TriggerGroupManager::createTriggerGroup(const std::string& name, const std::string& desc, bool generateId) {
	auto group = new Trigger::TriggerGroup(this, name, desc);
	group->setMapper(m_triggerGroupMapper);
	if(generateId)
		group->setId(m_triggerGroupMapper->getNextId());
	return group;
}

Trigger::TriggerGroup* TriggerGroupManager::findTriggerGroupById(DB::Id id) {
	return static_cast<Trigger::TriggerGroup*>(find(id));
}

Trigger::TriggerGroup* TriggerGroupManager::findTriggerGroupByName(const std::string& name) {
	Iterator it(this);
	while (it.hasNext()) {
		auto group = it.next();
		if (group->getName() == name) {
			return group;
		}
	}
	return nullptr;
}
