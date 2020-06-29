#include "DecExecutionContext.h"
#include "Decompiler.h"

using namespace CE::Decompiler;

void ExecutionBlockContext::setRegister(const Register& reg, ExprTree::Node* newExpr, bool rewrite) {
	if (m_registers.find(reg.m_reg) != m_registers.end()) {
		auto regExpr = m_registers[reg.m_reg];
		regExpr->removeBy(this); //multiple removes
	}

	if (newExpr) {
		m_registers[reg.m_reg] = newExpr;
		newExpr->addParentNode(this);
	}

	if (rewrite) {
		m_changedRegisters.insert(reg.m_reg);
	}

	for (auto sameReg : reg.m_sameRegisters) {
		auto it = m_cachedRegisters.find(sameReg.first);
		if (it != m_cachedRegisters.end()) {
			it->second->removeBy(&m_cachedRegisters);
		}
	}
}

RegisterParts ExecutionBlockContext::getRegisterParts(const Register& reg, uint64_t& mask, bool changedRegistersOnly) {
	RegisterParts regParts;
	for (auto sameReg : reg.m_sameRegisters) {
		auto reg = sameReg.first;
		if (changedRegistersOnly && m_changedRegisters.find(reg) == m_changedRegisters.end())
			continue;

		auto it = m_registers.find(reg);
		if (it != m_registers.end()) {
			auto sameRegMask = sameReg.second;
			auto changedRegMask = mask & ~sameRegMask;
			if (changedRegMask != mask) {
				auto part = new RegisterPart(sameRegMask, mask & sameRegMask, it->second);
				regParts.push_back(part);
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
		return m_cachedRegisters[reg.m_reg];
	}

	ExprTree::Node* regExpr;
	auto mask = reg.m_mask;
	auto regParts = getRegisterParts(reg, mask);
	if (mask) {
		auto symbol = new Symbol::RegisterVariable(reg.m_reg, reg.getSize());
		auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);
		auto externalSymbol = new ExternalSymbol(reg, mask, symbolLeaf, regParts);
		m_externalSymbols.push_back(externalSymbol);

		if (mask == reg.m_mask) {
			setRegister(reg, symbolLeaf, false);
		}
		regExpr = symbolLeaf;
	}
	else {
		regExpr = Register::CreateExprFromRegisterParts(regParts, reg.m_mask);
	}

	m_cachedRegisters[reg.m_reg] = regExpr;
	regExpr->addParentNode(&m_cachedRegisters);
	return regExpr;
}
