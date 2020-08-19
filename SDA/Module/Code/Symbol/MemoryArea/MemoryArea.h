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

			void addSymbol(MemorySymbol* memSymbol, int64_t offset);

			std::pair<int64_t, MemorySymbol*> getSymbolAt(int64_t offset);

			std::map<int64_t, MemorySymbol*>::iterator getSymbolIterator(int64_t offset);

			std::map<int64_t, MemorySymbol*>& getSymbols();
		private:
			MemoryAreaType m_type;
			int m_size;
			std::map<int64_t, MemorySymbol*> m_symbols;
			MemoryAreaManager* m_manager;
		};
	};
};