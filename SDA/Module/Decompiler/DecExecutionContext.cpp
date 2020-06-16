#include "DecExecutionContext.h"
#include "Decompiler.h"

using namespace CE::Decompiler;

void ExecutionBlockContext::setRegister(const Register& reg, ExprTree::Node* expr) {
	m_registers[reg.m_reg] = new WrapperNode(expr);

	for (auto sameReg : reg.m_sameRegisters) {
		m_cachedRegisters.erase(sameReg.first);
	}
}

ExprTree::Node* ExecutionBlockContext::requestRegister(const Register& reg) {
	if (m_cachedRegisters.find(reg.m_reg) != m_cachedRegisters.end()) {
		return m_cachedRegisters[reg.m_reg]->m_node;
	}

	auto regExpr = m_decompiler->requestRegister(reg);
	if (regExpr == nullptr) {
		Symbol::Symbol* symbol = new Symbol::LocalRegVar(reg.m_reg);
		regExpr = new ExprTree::SymbolLeaf(symbol);
		setRegister(reg, regExpr);
	}
	m_cachedRegisters[reg.m_reg] = new WrapperNode(regExpr);

	return regExpr;
}
