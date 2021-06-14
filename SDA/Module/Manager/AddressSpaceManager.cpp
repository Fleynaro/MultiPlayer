#include "AddressSpaceManager.h"
#include <DB/Mappers/AddressSpaceMapper.h>

using namespace CE;

CE::AddressSpaceManager::AddressSpaceManager(Project* project)
	: AbstractItemManager(project)
{
	m_imageMapper = new DB::AddressSpaceMapper(this);
}

AddressSpace* CE::AddressSpaceManager::createAddressSpace(const std::string& name, const std::string& desc, bool generateId) {
	auto addressSpace = new AddressSpace(this, name, desc);
	addressSpace->setMapper(m_imageMapper);
	if (generateId)
		addressSpace->setId(m_imageMapper->getNextId());
	return addressSpace;
}

void CE::AddressSpaceManager::loadAddressSpaces() {
	m_imageMapper->loadAll();
}

AddressSpace* CE::AddressSpaceManager::findAddressSpaceById(DB::Id id) {
	return dynamic_cast<AddressSpace*>(find(id));
}

AddressSpace* CE::AddressSpaceManager::findAddressSpaceByName(const std::string& name) {
	Iterator it(this);
	while (it.hasNext()) {
		auto item = it.next();
		if (item->getName() == name) {
			return item;
		}
	}
	throw ItemNotFoundException();
}
