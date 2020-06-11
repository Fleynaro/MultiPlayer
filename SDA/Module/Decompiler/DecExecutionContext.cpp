#include "DecExecutionContext.h"
#include "Decompiler.h"

using namespace CE::Decompiler;

void ExecutionBlockContext::setRegister(ZydisRegister reg, ExprTree::Node* expr) {
	m_registers[reg] = expr;
	m_cachedRegisters.erase(reg);
}

ExprTree::Node* ExecutionBlockContext::getRegister(ZydisRegister reg) {
	if (m_cachedRegisters.find(reg) != m_cachedRegisters.end()) {
		return m_cachedRegisters[reg];
	}
	auto regExpr = m_decompiler->requestRegister(reg);
	if (regExpr != nullptr) {
		m_cachedRegisters[reg] = regExpr;
	}
	return regExpr;
}
