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

		void createMainGlobalMemoryArea(int size);

		Symbol::MemoryArea* createMemoryArea(Symbol::MemoryArea::MemoryAreaType type, int size);

		Symbol::MemoryArea* getMemoryAreaById(DB::Id id);

		Symbol::MemoryArea* getMainGlobalMemoryArea();

	private:
		Symbol::MemoryArea* m_globalMemoryArea = nullptr;
		DB::MemoryAreaMapper* m_memoryAreaMapper;
	};
};