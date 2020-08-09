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
			enum Type {
				GLOBAL_SPACE = 1,
				STACK_SPACE = 2
			};

			MemoryArea(MemoryAreaManager* manager, Type type, int size)
				: m_manager(manager), m_type(type), m_size(size)
			{}

			MemoryAreaManager* getManager() {
				return m_manager;
			}

			Type getType() {
				return m_type;
			}

			int getSize() {
				return m_size;
			}

			void addSymbol(MemorySymbol* memSymbol, int offset) {
				memSymbol->setMemoryArea(this);
				m_symbols.insert(std::make_pair(offset, memSymbol));
			}

			MemorySymbol* getSymbolAt(int offset) {

			}

			std::map<int, MemorySymbol*>& getSymbols() {
				return m_symbols;
			}
		private:
			Type m_type;
			int m_size;
			std::map<int, MemorySymbol*> m_symbols;
			MemoryAreaManager* m_manager;
		};
	};
};