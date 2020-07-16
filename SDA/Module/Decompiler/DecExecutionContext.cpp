#include "DecExecutionContext.h"
#include "Decompiler.h"

using namespace CE::Decompiler;

ExecutionBlockContext::ExecutionBlockContext(Decompiler* decompiler)
	: m_decompiler(decompiler)
{}

void ExecutionBlockContext::setVarnode(PCode::Varnode* varnode, ExprTree::Node* newExpr, bool rewrite) {
	WrapperNode<ExprTree::Node>* oldWrapperNode = nullptr;
	for (auto it = m_varnodes.begin(); it != m_varnodes.end(); it ++) {
		if (it->equal(varnode)) {
			oldWrapperNode = it->m_expr;
			m_varnodes.erase(it);
			break;
		}
	}

	if (newExpr) {
		auto varnodeExpr = VarnodeExpr(varnode, new WrapperNode<ExprTree::Node>(newExpr), rewrite);
		m_varnodes.push_back(varnodeExpr);
	}

	if (oldWrapperNode) {
		//delete only here because new expr may be the same as old expr
		delete oldWrapperNode;
	}

	if (auto varnodeRegister = dynamic_cast<PCode::RegisterVarnode*>(varnode)) {
		for (auto it = m_cachedRegisters.begin(); it != m_cachedRegisters.end(); it ++) {
			if (it->first.getGenericId() == varnodeRegister->m_register.getGenericId()) {
				delete it->second;
				m_cachedRegisters.erase(it);
			}
		}
	}
}

RegisterParts ExecutionBlockContext::getRegisterParts(const PCode::Register& reg, uint64_t& mask, bool changedRegistersOnly) {
	RegisterParts regParts;
	for (auto it : m_varnodes) {
		if (changedRegistersOnly && !it.m_changed)
			continue;

		if (auto sameReg = dynamic_cast<PCode::RegisterVarnode*>(it.m_varnode)) {
			if (reg.getGenericId() == sameReg->m_register.getGenericId()) {
				//exception: eax(no ax, ah, al!) overwrite rax!!!
				auto sameRegMask = sameReg->m_register.m_valueRangeMask;
				auto remainToReadMask = mask & ~GetMaskWithException(sameRegMask);
				if (remainToReadMask != mask) {
					auto part = new RegisterPart(sameRegMask, mask & GetMaskWithException(sameRegMask), it.m_expr->m_node);
					regParts.push_back(part);
					mask = remainToReadMask;
				}
			}
		}

		if (mask == 0)
			break;
	}
	return regParts;
}

ExprTree::Node* ExecutionBlockContext::requestRegisterExpr(PCode::RegisterVarnode* varnodeRegister) {
	auto it = m_cachedRegisters.find(varnodeRegister->m_register);
	if (it != m_cachedRegisters.end()) {
		return it->second->m_node;
	}

	ExprTree::Node* regExpr;
	auto& reg = varnodeRegister->m_register;
	auto mask = varnodeRegister->m_register.m_valueRangeMask;
	auto regParts = getRegisterParts(reg, mask);
	if (mask) {
		auto symbol = new Symbol::RegisterVariable(reg, reg.getSize());
		auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);
		auto externalSymbol = new ExternalSymbol(reg, mask, symbolLeaf, regParts);
		m_externalSymbols.push_back(externalSymbol);

		if (mask == reg.m_valueRangeMask) {
			setVarnode(varnodeRegister, symbolLeaf, false);
		}
		regExpr = symbolLeaf;
	}
	else {
		regExpr = CreateExprFromRegisterParts(regParts, reg.m_valueRangeMask);
	}

	m_cachedRegisters[varnodeRegister->m_register] = new WrapperNode<ExprTree::Node>(regExpr);
	return regExpr;
}

ExprTree::Node* ExecutionBlockContext::requestSymbolExpr(PCode::SymbolVarnode* symbolVarnode)
{
	for (auto it = m_varnodes.begin(); it != m_varnodes.end(); it++) {
		if (symbolVarnode == it->m_varnode) {
			return it->m_expr->m_node;
		}
	}
	return nullptr;
}
