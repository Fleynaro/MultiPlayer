#pragma once
#include "../MemorySymbol.h"

namespace CE
{
	class MemoryAreaManager;

	namespace Symbol
	{
		class MemoryArea : public DB::DomainObject
		{
		public:
			enum MemoryAreaType {
				GLOBAL_SPACE = 1,
				STACK_SPACE = 2
			};

			MemoryArea(MemoryAreaManager* manager, MemoryAreaType type, int size);

			MemoryAreaManager* getManager();

			MemoryAreaType getType();

			int getSize();

			void addSymbol(MemorySymbol* memSymbol, int offset);

			std::pair<int, MemorySymbol*> getSymbolAt(int offset);

			std::map<int, MemorySymbol*>::iterator getSymbolIterator(int offset);

			std::map<int, MemorySymbol*>& getSymbols();
		private:
			MemoryAreaType m_type;
			int m_size;
			std::map<int, MemorySymbol*> m_symbols;
			MemoryAreaManager* m_manager;
		};
	};
};