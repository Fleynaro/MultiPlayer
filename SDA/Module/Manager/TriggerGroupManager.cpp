#include "TriggerGroupManager.h"
#include <DB/Mappers/TriggerGroupMapper.h>

using namespace CE;

TriggerGroupManager::TriggerGroupManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_triggerGroupMapper = new DB::TriggerGroupMapper(this);
}

void TriggerGroupManager::loadTriggerGroups()
{
	m_triggerGroupMapper->loadAll();
}

Trigger::TriggerGroup* TriggerGroupManager::createTriggerGroup(const std::string& name, const std::string& desc) {
	auto group = new Trigger::TriggerGroup(name, desc);
	group->setMapper(m_triggerGroupMapper);
	getProgramModule()->getTransaction()->markAsNew(group);
	return group;
}

Trigger::TriggerGroup* TriggerGroupManager::getTriggerGroupById(DB::Id id) {
	return static_cast<Trigger::TriggerGroup*>(find(id));
}

Trigger::TriggerGroup* TriggerGroupManager::getTriggerGroupByName(const std::string& name) {
	Iterator it(this);
	while (it.hasNext()) {
		auto group = it.next();
		if (group->getName() == name) {
			return group;
		}
	}
	return nullptr;
}
