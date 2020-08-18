#include "DecSymbol.h"
#include "ExprTree/ExprTreeFuncCallContext.h"
#include "DecCodeGraph.h"

using namespace CE::Decompiler;
using namespace CE::Decompiler::Symbol;

CE::Decompiler::Symbol::Symbol::~Symbol() {
	m_decGraph->removeSymbol(this);
}

std::list<PCode::Instruction*> FunctionResultVar::getInstructionsRelatedTo() {
	return { m_funcCallContext->m_instr };
}

std::string FunctionResultVar::printDebug() {
	return "[funcVar_" + std::to_string(m_id) + "_" + std::to_string(getSize() * 8) + "]";
}

std::list<PCode::Instruction*> MemoryVariable::getInstructionsRelatedTo() {
	return m_loadValueExpr->getInstructionsRelatedTo();
}
