#pragma once
#include "../DecSymbol.h"
#include <Code/Symbol/Symbol.h>

namespace CE::Decompiler::Symbol
{
	class SdaSymbol : public Symbol
	{
	public:
		SdaSymbol(CE::Symbol::AbstractSymbol* sdaSymbol)
			: m_sdaSymbol(sdaSymbol)
		{}

		int getSize() override {
			return m_sdaSymbol->getDataType()->getSize();
		}

		CE::Symbol::AbstractSymbol* getSdaSymbol() {
			return m_sdaSymbol;
		}
	private:
		CE::Symbol::AbstractSymbol* m_sdaSymbol;
	};
};