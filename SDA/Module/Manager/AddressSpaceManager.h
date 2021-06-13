#pragma once
#include "AbstractManager.h"
#include <Address/AddressSpace.h>

namespace DB {
	class AddressSpaceMapper;
};

namespace CE
{
	class AddressSpaceManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<AddressSpace>;

		AddressSpaceManager(Project* project)
			: AbstractItemManager(project)
		{
			m_imageMapper = new DB::AddressSpaceMapper(this);
		}

		AddressSpace* createAddressSpace(const std::string& name, const std::string& desc = "", bool generateId = true) {
			auto addressSpace = new AddressSpace(name, desc);
			addressSpace->setMapper(m_imageMapper);
			if (generateId)
				addressSpace->setId(m_imageMapper->getNextId());
			return addressSpace;
		}

		void loadAddressSpaces() {
			m_imageMapper->loadAll();
		}

		AddressSpace* findAddressSpaceById(DB::Id id) {
			return dynamic_cast<AddressSpace*>(find(id));
		}

		AddressSpace* findAddressSpaceByName(const std::string& name) {
			Iterator it(this);
			while (it.hasNext()) {
				auto item = it.next();
				if (item->getName() == name) {
					return item;
				}
			}
			throw ItemNotFoundException();
		}

	private:
		DB::AddressSpaceMapper* m_imageMapper;
	};
};