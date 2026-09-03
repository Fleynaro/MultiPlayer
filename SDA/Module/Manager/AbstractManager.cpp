#include "AbstractManager.h"

using namespace CE;

AbstractItemManager::AbstractItemManager(ProgramModule* programModule)
	: AbstractManager(programModule)
{}

void AbstractItemManager::onLoaded(DB::IDomainObject* obj) {
	m_items.insert(std::make_pair(obj->getId(), obj));
}

void AbstractItemManager::onChangeBeforeCommit(DB::IDomainObject* obj, ChangeType type) {
	switch (type)
	{
	case Inserted:
		if (m_items.find(obj->getId()) != m_items.end())
			throw std::exception("item has been already in the manager");
		m_items.insert(std::make_pair(obj->getId(), obj));
		break;
	case Removed:
		m_items.erase(obj->getId());
		break;
	}
}

void AbstractItemManager::onChangeAfterCommit(DB::IDomainObject* obj, ChangeType type) {
}

DB::IDomainObject* AbstractItemManager::find(DB::Id id) {
	if (m_items.find(id) == m_items.end())
		return nullptr;
	return m_items[id];
}

int AbstractItemManager::getItemsCount() {
	return (int)m_items.size();
}

AbstractManager::AbstractManager(ProgramModule* programModule)
	: m_programModule(programModule)
{}

ProgramModule* AbstractManager::getProgramModule() {
	return m_programModule;
}
