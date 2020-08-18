#include "MemoryAreaManager.h"
#include <DB/Mappers/MemoryAreaMapper.h>

using namespace CE;
using namespace Symbol;

MemoryAreaManager::MemoryAreaManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_memoryAreaMapper = new DB::MemoryAreaMapper(this);
}

void MemoryAreaManager::loadMemoryAreas() {
	m_memoryAreaMapper->loadAll();

	//find the first global memory area and set it
	Iterator it(this);
	while (it.hasNext()) {
		auto memoryArea = it.next();
		if (memoryArea->getType() == MemoryArea::GLOBAL_SPACE) {
			m_globalMemoryArea = memoryArea;
			break;
		}
	}
}

void MemoryAreaManager::createMainGlobalMemoryArea(int size) {
	m_globalMemoryArea = createMemoryArea(MemoryArea::GLOBAL_SPACE, size);
}

MemoryArea* MemoryAreaManager::createMemoryArea(MemoryArea::MemoryAreaType type, int size) {
	auto symbol = new MemoryArea(this, type, size);
	symbol->setMapper(m_memoryAreaMapper);
	symbol->setId(m_memoryAreaMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(symbol);
	return symbol;
}

MemoryArea* MemoryAreaManager::getMemoryAreaById(DB::Id id) {
	return static_cast<MemoryArea*>(find(id));
}

Symbol::MemoryArea* MemoryAreaManager::getMainGlobalMemoryArea() {
	return m_globalMemoryArea;
}

