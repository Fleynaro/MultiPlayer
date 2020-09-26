#pragma once
#include "AbstractSymbol.h"
#include <Decompiler/DecStorage.h>

namespace CE::Symbol
{
	class IMemorySymbol : virtual public ISymbol
	{
	public:
		virtual std::list<Decompiler::Storage> getStorages() = 0;
	};
};