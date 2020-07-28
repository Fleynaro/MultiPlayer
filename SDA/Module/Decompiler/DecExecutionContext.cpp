#include "DecExecutionContext.h"
#include "Decompiler.h"

using namespace CE::Decompiler;

ExecutionBlockContext::ExecutionBlockContext(Decompiler* decompiler)
	: m_decompiler(decompiler)
{}

void ExecutionBlockContext::setVarnode(const PCode::Register& reg, ExprTree::Node * expr, bool rewrite)
{
	auto varnode = new PCode::RegisterVarnode(reg);
	m_ownRegVarnodes.push_back(varnode);
	return setVarnode(varnode, expr, rewrite);
}

void ExecutionBlockContext::setVarnode(PCode::Varnode* varnode, ExprTree::Node* newExpr, bool rewrite) {
	std::list<WrapperNode<ExprTree::Node>*> oldWrapperNodes;
	
	//remove all old registers/symbols
	if (auto varnodeRegister = dynamic_cast<PCode::RegisterVarnode*>(varnode)) {
		//write rax -> remove eax/ax/ah/al
		auto& reg = varnodeRegister->m_register;
		for (auto it = m_varnodes.begin(); it != m_varnodes.end(); it++) {
			if (auto sameRegVarnode = dynamic_cast<PCode::RegisterVarnode*>(it->m_varnode)) {
				if (reg.getGenericId() == sameRegVarnode->m_register.getGenericId()) {
					if ((GetMaskWithException(sameRegVarnode->m_register.m_valueRangeMask) & ~GetMaskWithException(reg.m_valueRangeMask)) == 0) {
						oldWrapperNodes.push_back(it->m_expr);
						m_varnodes.erase(it);
					}
				}
			}
		}

		for (auto it = m_cachedRegisters.begin(); it != m_cachedRegisters.end(); it++) {
			if (it->first.getGenericId() == varnodeRegister->m_register.getGenericId()) {
				oldWrapperNodes.push_back(it->second);
				m_cachedRegisters.erase(it);
			}
		}
	} else if (auto varnodeSymbol = dynamic_cast<PCode::SymbolVarnode*>(varnode)) {
		for (auto it = m_varnodes.begin(); it != m_varnodes.end(); it++) {
			if (it->m_varnode == varnodeSymbol) {
				oldWrapperNodes.push_back(it->m_expr);
				m_varnodes.erase(it);
				break;
			}
		}
	}

	//set new register/symbol
	if (newExpr) {
		auto varnodeExpr = VarnodeExpr(varnode, new WrapperNode<ExprTree::Node>(newExpr), rewrite);
		m_varnodes.push_back(varnodeExpr);
	}
	
	//delete only here because new expr may be the same as old expr: mov rax, rax
	for (auto it : oldWrapperNodes) {
		delete it;
	}
}

RegisterParts ExecutionBlockContext::getRegisterParts(const PCode::Register& reg, uint64_t& mask, bool changedRegistersOnly) {
	RegisterParts regParts;
	using SameRegInfo = std::pair<PCode::Register, ExprTree::Node*>;
	std::list<SameRegInfo> sameRegisters;
	//select same registeres
	for (auto it : m_varnodes) {
		if (changedRegistersOnly && !it.m_changed)
			continue;
		if (auto sameRegVarnode = dynamic_cast<PCode::RegisterVarnode*>(it.m_varnode)) {
			if (reg.getGenericId() == sameRegVarnode->m_register.getGenericId()) {
				sameRegisters.push_back(std::make_pair(sameRegVarnode->m_register, it.m_expr->m_node));
			}
		}
	}

	//sort asc
	sameRegisters.sort([](SameRegInfo a, SameRegInfo b) {
		return a.first.m_valueRangeMask < b.first.m_valueRangeMask;
		});

	//gather need parts
	for (auto sameRegInfo : sameRegisters) {
		//exception: eax(no ax, ah, al!) overwrite rax!!!
		auto sameRegMask = sameRegInfo.first.m_valueRangeMask;
		auto sameRegExceptionMask = GetMaskWithException(sameRegMask); //for x86 only!!!
		auto remainToReadMask = mask & ~sameRegExceptionMask;
		if (remainToReadMask != mask) {
			auto part = new RegisterPart(sameRegMask, mask & sameRegExceptionMask, sameRegInfo.second);
			regParts.push_back(part);
			mask = remainToReadMask;
		}

		if (mask == 0)
			break;
	}
	return regParts;
}

ExprTree::Node* ExecutionBlockContext::requestRegisterExpr(PCode::RegisterVarnode* varnodeRegister) {
	for (auto it : m_cachedRegisters) {
		if (it.first == varnodeRegister->m_register) {
			return it.second->m_node;
		}
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
		regExpr = CreateExprFromRegisterParts(regParts, reg.m_valueRangeMask, reg.isVector());
	}

	m_cachedRegisters.push_back(std::make_pair(varnodeRegister->m_register, new WrapperNode<ExprTree::Node>(regExpr)));
	return regExpr;
}

ExprTree::Node* ExecutionBlockContext::requestRegisterExpr(const PCode::Register& reg)
{
	auto varnode = new PCode::RegisterVarnode(reg);
	m_ownRegVarnodes.push_back(varnode);
	return requestRegisterExpr(varnode);
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
