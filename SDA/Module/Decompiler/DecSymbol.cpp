#include "DecSymbol.h"
#include "ExprTree/ExprTree.h"
#include "Graph/DecCodeGraph.h"

using namespace CE::Decompiler;
using namespace CE::Decompiler::Symbol;

CE::Decompiler::Symbol::Symbol::~Symbol() {
	m_decGraph->removeSymbol(this);
}

CE::Decompiler::Symbol::Symbol* CE::Decompiler::Symbol::Symbol::clone(ExprTree::NodeCloneContext* ctx) {
	if (!ctx->m_cloneSymbols)
		return this;
	auto it = ctx->m_clonedSymbols.find(this);
	if (it != ctx->m_clonedSymbols.end())
		return it->second;
	auto newSymbol = cloneSymbol();
	ctx->m_clonedSymbols.insert(std::make_pair(this, newSymbol));
	if (auto symbolWithId = dynamic_cast<SymbolWithId*>(this)) {
		dynamic_cast<SymbolWithId*>(newSymbol)->setId(symbolWithId->getId());
	}
	return newSymbol;
}