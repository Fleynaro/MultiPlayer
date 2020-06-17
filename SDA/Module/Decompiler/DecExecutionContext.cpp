#include "DecExecutionContext.h"
#include "Decompiler.h"

using namespace CE::Decompiler;

void ExecutionBlockContext::setRegister(const Register& reg, ExprTree::Node* expr) {
	if (m_registers.find(reg.m_reg) != m_registers.end()) {
		auto wrapperNode = m_registers[reg.m_reg];
		wrapperNode->m_node->removeBy(wrapperNode);
		wrapperNode->m_node = expr;
		expr->addParentNode(wrapperNode);
	}
	else {
		m_registers[reg.m_reg] = new ExprTree::WrapperNode(expr);
	}

	for (auto sameReg : reg.m_sameRegisters) {
		m_cachedRegisters.erase(sameReg.first);
	}
}

std::list<RegisterPart> ExecutionBlockContext::getRegisterParts(const Register& reg, uint64_t& mask) {
	std::list<RegisterPart> regParts;
	for (auto sameReg : reg.m_sameRegisters) {
		auto reg = sameReg.first;
		auto it = m_registers.find(reg);
		if (it != m_registers.end()) {
			auto sameRegMask = sameReg.second;
			auto changedRegMask = mask & ~sameRegMask;
			if (changedRegMask != mask) {
				RegisterPart info;
				info.regMask = sameRegMask;
				info.maskToChange = mask & sameRegMask;
				info.expr = it->second;
				regParts.push_back(info);
				mask = changedRegMask;
			}
		}

		if (mask == 0)
			break;
	}
	return regParts;
}

ExprTree::Node* ExecutionBlockContext::requestRegister(const Register& reg) {
	if (m_cachedRegisters.find(reg.m_reg) != m_cachedRegisters.end()) {
		return m_cachedRegisters[reg.m_reg]->m_node;
	}

	ExprTree::Node* regExpr;
	auto mask = reg.m_mask;
	auto regParts = getRegisterParts(reg, mask);
	if (mask) {
		auto symbol = new Symbol::LocalRegVar(reg.m_reg);
		auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);
		auto externalSymbol = new ExternalSymbol(reg, mask, symbolLeaf, regParts);
		m_externalSymbols.push_back(externalSymbol);
		regExpr = symbolLeaf;
	}
	else {
		regExpr = Register::CreateExprFromRegisterParts(regParts, reg.m_mask);
	}

	//new ExprTree::WrapperNode???
	auto wrapperNode = new ExprTree::WrapperNode(regExpr);
	if (mask == reg.m_mask) {
		m_registers[reg.m_reg] = wrapperNode; //???
	}
	m_cachedRegisters[reg.m_reg] = wrapperNode;
	return regExpr;
}
