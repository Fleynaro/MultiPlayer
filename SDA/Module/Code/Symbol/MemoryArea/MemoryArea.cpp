#include "MemoryArea.h"

using namespace CE;
using namespace CE::Symbol;

MemoryArea::MemoryArea(MemoryAreaManager* manager, MemoryAreaType type, int size)
	: m_manager(manager), m_type(type), m_size(size)
{}

MemoryAreaManager* MemoryArea::getManager() {
	return m_manager;
}

MemoryArea::MemoryAreaType MemoryArea::getType() {
	return m_type;
}

int MemoryArea::getSize() {
	return m_size;
}

void MemoryArea::addSymbol(MemorySymbol* memSymbol, int64_t offset) {
	memSymbol->setMemoryArea(this);
	m_symbols.insert(std::make_pair(offset, memSymbol));
}

std::pair<int64_t, MemorySymbol*> MemoryArea::getSymbolAt(int64_t offset) {
	auto it = getSymbolIterator(offset);
	if (it != m_symbols.end())
		return std::make_pair(it->first, it->second);
	return std::make_pair(0, nullptr);
}

std::map<int64_t, MemorySymbol*>::iterator MemoryArea::getSymbolIterator(int64_t offset) {
	auto it = std::prev(m_symbols.upper_bound(offset));
	if (it != m_symbols.end()) {
		auto symbolOffset = it->first;
		auto symbol = it->second;
		if (offset < symbolOffset + symbol->getSize()) {
			return it;
		}
	}
	return m_symbols.end();
}

std::map<int64_t, MemorySymbol*>& MemoryArea::getSymbols() {
	return m_symbols;
}
