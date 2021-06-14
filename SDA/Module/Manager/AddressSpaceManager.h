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

		AddressSpaceManager(Project* project);

		AddressSpace* createAddressSpace(const std::string& name, const std::string& desc = "", bool generateId = true);

		void loadAddressSpaces();

		AddressSpace* findAddressSpaceById(DB::Id id);

		AddressSpace* findAddressSpaceByName(const std::string& name);

	private:
		DB::AddressSpaceMapper* m_imageMapper;
	};
};