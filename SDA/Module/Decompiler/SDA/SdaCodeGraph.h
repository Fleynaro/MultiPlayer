#pragma once
#include "../Graph/DecCodeGraph.h"
#include "AutoSdaSymbol.h"
#include "ExprTree/ExprTreeSda.h"
#include "../ExprTree/ExprTree.h"

namespace CE::Decompiler
{
	class SdaCodeGraph
	{
	public:
		SdaCodeGraph(DecompiledCodeGraph* decGraph)
			: m_decGraph(decGraph)
		{}

		DecompiledCodeGraph* getDecGraph() {
			return m_decGraph;
		}

		/*CE::Symbol::AbstractSymbol* findSdaSymbolByName(std::string name) {
			for (auto symbol : m_sdaSymbols) {
				if (name == symbol->getName())
					return symbol;
			}
			return nullptr;
		}*/

		std::list<CE::Symbol::AbstractSymbol*>& getSdaSymbols() {
			return m_sdaSymbols;
		}
	private:
		DecompiledCodeGraph* m_decGraph;
		std::list<CE::Symbol::AbstractSymbol*> m_sdaSymbols;
	};

};