#include "PCodeExecutionContext.h"
#include "../../Decompiler.h"

using namespace CE::Decompiler;

ExecutionBlockContext::ExecutionBlockContext(Decompiler* decompiler)
	: m_decompiler(decompiler)
{}

void ExecutionBlockContext::setVarnode(const PCode::Register& reg, ExprTree::INode * expr, bool rewrite)
{
	auto varnode = new PCode::RegisterVarnode(reg);
	m_ownRegVarnodes.push_back(varnode);
	return setVarnode(varnode, expr, rewrite);
}

void ExecutionBlockContext::setVarnode(PCode::Varnode* varnode, ExprTree::INode* newExpr, bool rewrite) {
	std::list<TopNode*> oldTopNodes;
	
	//remove all old registers/symbols
	if (auto varnodeRegister = dynamic_cast<PCode::RegisterVarnode*>(varnode)) {
		//write rax -> remove eax/ax/ah/al
		auto& reg = varnodeRegister->m_register;
		for (auto it = m_varnodes.begin(); it != m_varnodes.end(); it++) {
			if (auto sameRegVarnode = dynamic_cast<PCode::RegisterVarnode*>(it->m_varnode)) {
				if (reg.intersect(sameRegVarnode->m_register)) {
					oldTopNodes.push_back(it->m_expr);
					m_varnodes.erase(it);
				}
			}
		}

		for (auto it = m_cachedRegisters.begin(); it != m_cachedRegisters.end(); it++) {
			if (reg.intersect(it->first)) {
				oldTopNodes.push_back(it->second);
				m_cachedRegisters.erase(it);
			}
		}
	} else if (auto varnodeSymbol = dynamic_cast<PCode::SymbolVarnode*>(varnode)) {
		for (auto it = m_varnodes.begin(); it != m_varnodes.end(); it++) {
			if (it->m_varnode == varnodeSymbol) {
				oldTopNodes.push_back(it->m_expr);
				m_varnodes.erase(it);
				break;
			}
		}
	}

	//set new register/symbol
	if (newExpr) {
		auto varnodeExpr = VarnodeExpr(varnode, new TopNode(newExpr), rewrite);
		m_varnodes.push_back(varnodeExpr);
	}
	
	//delete only here because new expr may be the same as old expr: mov rax, rax
	for (auto it : oldTopNodes) {
		delete it;
	}
}

RegisterParts ExecutionBlockContext::getRegisterParts(PCode::RegisterId registerId, ExtBitMask& needReadMask, bool changedRegistersOnly) {
	RegisterParts regParts;
	using SameRegInfo = std::pair<PCode::Register, ExprTree::INode*>;
	std::list<SameRegInfo> sameRegisters;
	//select same registeres
	for (auto it : m_varnodes) {
		if (auto sameRegVarnode = dynamic_cast<PCode::RegisterVarnode*>(it.m_varnode)) {
			if (registerId == sameRegVarnode->m_register.getGenericId()) {
				if (!it.m_changed) {
					if (changedRegistersOnly)
						continue;
					//to avoide ([rcx] & 0xFF00) | ([rcx] & 0xFF)
					if (!m_resolvedExternalSymbols.empty()) {
						if (!(needReadMask & ~sameRegVarnode->m_register.m_valueRangeMask).isZero()) {
							if (m_resolvedExternalSymbols.find(sameRegVarnode) != m_resolvedExternalSymbols.end())
								continue;
						}
					}
				}
				sameRegisters.push_back(std::make_pair(sameRegVarnode->m_register, it.m_expr->getNode()));
			}
		}
	}

	//sort asc
	sameRegisters.sort([](SameRegInfo& a, SameRegInfo& b) {
		return a.first.m_valueRangeMask < b.first.m_valueRangeMask;
		});

	//gather need parts
	for (auto sameRegInfo : sameRegisters) {
		auto& sameReg = sameRegInfo.first;
		auto sameRegExceptionMask = GetValueRangeMaskWithException(sameReg); //for x86 only!!!
		//if the masks intersected
		if (!(needReadMask & sameRegExceptionMask).isZero()) {
			auto part = new RegisterPart(sameReg.m_valueRangeMask, needReadMask & sameRegExceptionMask, sameRegInfo.second);
			regParts.push_back(part);
			needReadMask = needReadMask & ~sameRegExceptionMask;
		}

		if (needReadMask == 0)
			break;
	}
	return regParts;
}

ExprTree::INode* ExecutionBlockContext::requestRegisterExpr(PCode::RegisterVarnode* varnodeRegister) {
	for (auto it : m_cachedRegisters) {
		if (it.first == varnodeRegister->m_register) {
			return it.second->getNode();
		}
	}

	ExprTree::INode* regExpr;
	auto& reg = varnodeRegister->m_register;
	auto needReadMask = varnodeRegister->m_register.m_valueRangeMask;

	// try to get expr. value from register varnode within this exec. block context
	auto regParts = getRegisterParts(reg.getGenericId(), needReadMask);

	if (!needReadMask.isZero()) {
		// if not all register parts are got then it requires external symbol (need to address other exec. block contexts)
		auto symbol = new Symbol::RegisterVariable(reg);
		m_decompiler->m_decompiledGraph->addSymbol(symbol);
		auto symbolLeaf = new ExprTree::SymbolLeaf(symbol);
		auto externalSymbol = new ExternalSymbol(varnodeRegister, needReadMask, symbolLeaf, regParts);
		m_externalSymbols.push_back(externalSymbol);

		if (needReadMask == reg.m_valueRangeMask) {
			setVarnode(varnodeRegister, symbolLeaf, false);
		}
		regExpr = symbolLeaf;
	}
	else {
		// if all register parts are got then combine them into one expr. value
		regExpr = CreateExprFromRegisterParts(regParts, reg.m_valueRangeMask);
	}

	m_cachedRegisters.push_back(std::make_pair(varnodeRegister->m_register, new TopNode(regExpr)));
	return regExpr;
}

ExprTree::INode* ExecutionBlockContext::requestRegisterExpr(const PCode::Register& reg)
{
	auto varnode = new PCode::RegisterVarnode(reg);
	m_ownRegVarnodes.push_back(varnode);
	return requestRegisterExpr(varnode);
}

ExprTree::INode* ExecutionBlockContext::requestSymbolExpr(PCode::SymbolVarnode* symbolVarnode)
{
	for (auto it = m_varnodes.begin(); it != m_varnodes.end(); it++) {
		if (symbolVarnode == it->m_varnode) {
			return it->m_expr->getNode();
		}
	}
	return nullptr;
}
