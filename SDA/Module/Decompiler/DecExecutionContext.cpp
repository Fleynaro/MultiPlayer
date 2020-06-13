#include "DecExecutionContext.h"
#include "Decompiler.h"

using namespace CE::Decompiler;

void ExecutionBlockContext::setRegister(const Register::RegInfo& regInfo, ZydisRegister reg, ExprTree::Node* expr) {
	m_registers[reg] = expr;

	for (auto sameReg : regInfo.m_sameRegisters) {
		m_cachedRegisters.erase(sameReg.first);
	}
}

ExprTree::Node* ExecutionBlockContext::requestRegister(ZydisRegister reg) {
	if (m_cachedRegisters.find(reg) != m_cachedRegisters.end()) {
		return m_cachedRegisters[reg];
	}

	auto regExpr = m_decompiler->requestRegister(reg);
	if (regExpr == nullptr) {
		Symbol::Symbol* symbol = new Symbol::LocalRegVar(reg);
		regExpr = new ExprTree::SymbolLeaf(symbol);
	}
	m_cachedRegisters[reg] = regExpr;

	return regExpr;
}
