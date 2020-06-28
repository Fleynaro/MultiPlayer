#include "Symbol.h"
#include "ExprTree/ExprTreeFuncCallContext.h"

using namespace CE::Decompiler;
using namespace CE::Decompiler::Symbol;

std::string FunctionResultVar::printDebug() {
	return "[funcVar_" + std::to_string(m_funcCallContext->m_destOffset + 50000000) + "_" + std::to_string(getSize() * 8) + "]";
}
