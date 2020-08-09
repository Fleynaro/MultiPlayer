#pragma once
#include "AbstractManager.h"
#include <Code/Symbol/MemoryArea/MemoryArea.h>

namespace DB {
	class MemoryAreaMapper;
};

namespace CE
{
	class MemoryAreaManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Symbol::MemoryArea>;

		MemoryAreaManager(ProgramModule* module);

		void loadMemoryAreas();

		Symbol::MemoryArea* createMemoryArea(Symbol::MemoryArea::Type type, int size);

		Symbol::MemoryArea* getMemoryAreaById(DB::Id id) {
			return static_cast<Symbol::MemoryArea*>(find(id));
		}

	private:
		DB::MemoryAreaMapper* m_memoryAreaMapper;
	};
};