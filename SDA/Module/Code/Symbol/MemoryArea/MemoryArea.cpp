#include "MemoryArea.h"

using namespace CE;
using namespace CE::Symbol;

SymbolTable::SymbolTable(SymbolTableManager* manager, SymbolTableType type, int size)
	: m_manager(manager), m_type(type), m_size(size)
{}

SymbolTableManager* SymbolTable::getManager() {
	return m_manager;
}

SymbolTable::SymbolTableType SymbolTable::getType() {
	return m_type;
}

int SymbolTable::getSize() {
	return m_size;
}

void SymbolTable::addSymbol(ISymbol* symbol, int64_t offset) {
	m_symbols.insert(std::make_pair(offset, symbol));
}

std::pair<int64_t, ISymbol*> SymbolTable::getSymbolAt(int64_t offset) {
	auto it = getSymbolIterator(offset);
	if (it != m_symbols.end())
		return std::make_pair(it->first, it->second);
	return std::make_pair(0, nullptr);
}

std::map<int64_t, ISymbol*>::iterator SymbolTable::getSymbolIterator(int64_t offset) {
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

std::map<int64_t, ISymbol*>& SymbolTable::getSymbols() {
	return m_symbols;
}
