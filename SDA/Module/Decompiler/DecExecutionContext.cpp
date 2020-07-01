#include "DecExecutionContext.h"
#include "Decompiler.h"

using namespace CE::Decompiler;

ExecutionBlockContext::ExecutionBlockContext(Decompiler* decompiler, int startOffset)
	: m_decompiler(decompiler), m_offset(startOffset)
{}

void ExecutionBlockContext::setRegister(const Register& reg, ExprTree::Node* newExpr, bool rewrite) {
	
	WrapperNode<ExprTree::Node>* oldWrapperNode = nullptr;
	auto it = m_registers.find(reg.m_reg);
	if (it != m_registers.end()) {
		oldWrapperNode = it->second;
		m_registers.erase(it);
	}

	if (newExpr) {
		m_registers[reg.m_reg] = new WrapperNode<ExprTree::Node>(newExpr);
	}

	if (rewrite) {
		m_changedRegisters.insert(reg.m_reg);
	}

	if (oldWrapperNode) {
		//delete only here because new expr may be the same as old expr
		delete oldWrapperNode;
	}

	for (auto sameReg : reg.m_sameRegisters) {
		auto it = m_cachedRegisters.find(sameReg.first);
		if (it != m_cachedRegisters.end()) {
			delete it->second;
			m_cachedRegisters.erase(it);
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
				auto part = new RegisterPart(sameRegMask, mask & sameRegMask, it->second->m_node);
				regParts.push_back(part);
				mask = changedRegMask;

				//exception: eax(no ax, ah, al!) overwrite rax!!!
				/*if (sameRegMask == 0xFFFFFFFF) {
					mask &= 0xFFFFFFFF;
				}*/
			}
		}

		if (mask == 0)
			break;
	}
	return regParts;
}

ExprTree::Node* ExecutionBlockContext::requestRegister(const Register& reg) {
	auto it = m_cachedRegisters.find(reg.m_reg);
	if (it != m_cachedRegisters.end()) {
		return it->second->m_node;
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

	m_cachedRegisters[reg.m_reg] = new WrapperNode<ExprTree::Node>(regExpr);
	return regExpr;
}

ExprTree::Condition* ExecutionBlockContext::getFlag(ZydisCPUFlag flag) {
	auto it = m_flags.find(flag);
	if (it == m_flags.end())
		return nullptr;
	return it->second->m_node;
}

void ExecutionBlockContext::setFlag(ZydisCPUFlag flag, ExprTree::Condition* cond) {
	WrapperNode<ExprTree::Condition>* oldWrapperNode = nullptr;
	auto it = m_flags.find(flag);
	if (it != m_flags.end()) {
		oldWrapperNode = it->second;
		m_flags.erase(it);
	}

	if (cond) {
		m_flags[flag] = new WrapperNode<ExprTree::Condition>(cond);
	}

	if (oldWrapperNode) {
		//delete only here because new expr may be the same as old expr
		delete oldWrapperNode;
	}
}

void ExecutionBlockContext::setLastCond(ExprTree::Node* leftNode, ExprTree::Node* rightNode, RegisterFlags flags) {
	if (m_lastCond.leftNode != nullptr) {
		m_lastCond.leftNode->removeBy(nullptr);
	}
	if (m_lastCond.rightNode != nullptr) {
		m_lastCond.rightNode->removeBy(nullptr);
	}
	m_lastCond.leftNode = leftNode;
	m_lastCond.rightNode = rightNode;
	m_lastCond.flags = flags;
}

void ExecutionBlockContext::clearLastCond() {
	setLastCond(nullptr, nullptr, RegisterFlags::None);
}
