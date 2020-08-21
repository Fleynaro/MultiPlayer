#include "DecSymbol.h"
#include "ExprTree/ExprTreeFuncCallContext.h"
#include "DecCodeGraph.h"

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

std::list<PCode::Instruction*> FunctionResultVar::getInstructionsRelatedTo() {
	return { m_funcCallContext->m_instr };
}

std::string FunctionResultVar::printDebug() {
	return "[funcVar_" + std::to_string(getId()) + "_" + std::to_string(getSize() * 8) + "]";
}

std::list<PCode::Instruction*> MemoryVariable::getInstructionsRelatedTo() {
	return m_loadValueExpr->getInstructionsRelatedTo();
}
