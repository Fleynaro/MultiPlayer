#pragma once
#include "../MemorySymbol.h"

namespace CE
{
	class SymbolTableManager;

	namespace Symbol
	{
		class SymbolTable : public DB::DomainObject
		{
		public:
			enum SymbolTableType {
				GLOBAL_SPACE = 1,
				STACK_SPACE = 2
			};

			SymbolTable(SymbolTableManager* manager, SymbolTableType type, int size);

			SymbolTableManager* getManager();

			SymbolTableType getType();

			int getSize();

			void addSymbol(AbstractSymbol* symbol, int64_t offset);

			std::pair<int64_t, AbstractSymbol*> getSymbolAt(int64_t offset);

			std::map<int64_t, AbstractSymbol*>::iterator getSymbolIterator(int64_t offset);

			std::map<int64_t, AbstractSymbol*>& getSymbols();
		private:
			SymbolTableType m_type;
			int m_size;
			std::map<int64_t, AbstractSymbol*> m_symbols;
			SymbolTableManager* m_manager;
		};
	};
};