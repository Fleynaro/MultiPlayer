#include "DecExecContext.h"
#include "PrimaryDecompiler.h"

using namespace CE::Decompiler;

ExprTree::INode* RegisterExecContext::requestRegister(const PCode::Register& reg) {
	BitMask64 needReadMask = reg.m_valueRangeMask;
	auto regParts = findRegisterParts(reg.getId(), needReadMask);
	if (!needReadMask.isZero()) {
		auto symbol = new Symbol::RegisterVariable(reg);
		m_decompiler->m_decompiledGraph->addSymbol(symbol);
		RegisterPart part;
		part.m_regMask = reg.m_valueRangeMask;
		part.m_maskToChange = needReadMask;
		part.m_expr = new ExprTree::SymbolLeaf(symbol);
		regParts.push_back(part);
	}

	return CreateExprFromRegisterParts(regParts, reg.m_valueRangeMask);
}

void RegisterExecContext::copyFrom(RegisterExecContext* ctx) {
	clear();

	auto decompiler = m_decompiler;
	auto execCtx = m_execContext;
	*this = *ctx;
	m_decompiler = decompiler;
	m_execContext = execCtx;
	m_isFilled = true;

	for (auto& pair : m_registers) {
		auto& registers = pair.second;
		for (auto& regInfo : registers) {
			regInfo.m_expr = new TopNode(regInfo.m_expr->getNode());
		}
	}
}

void RegisterExecContext::join(RegisterExecContext* ctx) {
	for (auto& pair : ctx->m_registers) {
		auto regId = pair.first;

		auto it = m_registers.find(regId);
		if (it != m_registers.end()) {
			std::list<RegisterInfo> neededRegs;
			auto regs1 = pair.second; // from ctx->m_registers
			auto& regs2 = it->second; // from m_registers

			// find equal registers with equal top nodes (expr), they are mutual
			for (auto it1 = regs1.begin(); it1 != regs1.end(); it1++) {
				for (auto it2 = regs2.begin(); it2 != regs2.end(); it2++) {
					if (it1->m_register == it2->m_register && it1->m_expr->getNode() == it2->m_expr->getNode()) {
						neededRegs.push_back(*it2);
						regs1.erase(it1);
						regs2.erase(it2);
						break;
					}
				}
			}

			// if there are registers which come from different blocks
			if (!regs1.empty() && !regs2.empty()) {
				// WAY 1 (single mask)
				auto mask1 = calculateMaxMask(regs1);
				auto mask2 = calculateMaxMask(regs2);
				auto resultMask = mask1 & mask2;
				auto resultMasks = { resultMask };

				// WAY 2 (multiple masks)
				// calculate masks which belongs to different groups with non-intersected registers.
				// need for XMM registers to split low and high parts into two independent local vars
				// auto resultMasks = CalculateMasks(regs1, regs2); // todo: does it need?

				for (auto resultMask : resultMasks)
				{
					// new register
					auto& sampleReg = regs1.begin()->m_register;
					auto newRegister = Register(sampleReg.getGenericId(), sampleReg.getIndex(), resultMask, sampleReg.getType());
					auto newUsing = RegisterInfo::REGISTER_NOT_USING;

					// parent contexts
					std::set<ExecContext*> newExecCtxs;

					// iterate over all register parts in two parent contexts
					Symbol::LocalVariable* existingLocalVar = nullptr;
					for (auto& regs : { regs1, regs2 }) {
						for (auto& regInfo : regs) {
							// add contexts
							if (regInfo.m_srcExecContext != m_execContext)
								newExecCtxs.insert(regInfo.m_srcExecContext);

							// change using state
							if (newUsing == RegisterInfo::REGISTER_NOT_USING) {
								if (regInfo.m_using == RegisterInfo::REGISTER_PARTIALLY_USING) {
									newUsing = RegisterInfo::REGISTER_PARTIALLY_USING;
								} else if (regInfo.m_using == RegisterInfo::REGISTER_FULLY_USING) {
									newUsing = RegisterInfo::REGISTER_FULLY_USING;
								}
							}
							else if (newUsing == RegisterInfo::REGISTER_FULLY_USING) {
								if (regInfo.m_using <= RegisterInfo::REGISTER_PARTIALLY_USING) {
									newUsing = RegisterInfo::REGISTER_PARTIALLY_USING;
								}
							}

							if (!existingLocalVar) {
								// find an exitsting symbol with need size for re-using
								std::list<ExprTree::SymbolLeaf*> symbolLeafs;
								GatherSymbolLeafsFromNode(regInfo.m_expr->getNode(), symbolLeafs);
								for (auto symbolLeaf : symbolLeafs) {
									if (auto localVar = dynamic_cast<Symbol::LocalVariable*>(symbolLeaf->m_symbol)) {
										auto& localVarInfo = m_decompiler->m_localVars[localVar];

										if (localVarInfo.m_register.intersect(newRegister)) {
											if (localVarInfo.m_register.m_valueRangeMask == newRegister.m_valueRangeMask) {
												existingLocalVar = localVar;
											}
											else {
												// when eax=localVar and ax=5 coming in
												if (regInfo.m_srcExecContext == m_execContext) {
													for (auto ctx : localVarInfo.m_execCtxs)
														newExecCtxs.insert(ctx);
												}
											}
											break;
										}
									}
								}
							}
						}
					}

					// new register info
					RegisterInfo registerInfo;
					registerInfo.m_register = newRegister;
					auto localVar = existingLocalVar;
					if (!localVar) {
						// new local var
						localVar = new Symbol::LocalVariable(resultMask.getSize());
						// info for par. assignments
						PrimaryDecompiler::LocalVarInfo localVarInfo;
						localVarInfo.m_register = newRegister;
						m_decompiler->m_localVars[localVar] = localVarInfo;
					}
					registerInfo.m_expr = new TopNode(new ExprTree::SymbolLeaf(localVar));
					registerInfo.m_srcExecContext = m_execContext;
					registerInfo.m_using = newUsing;

					// add parent contexts where par. assignments (localVar = 5) will be created
					auto& localVarInfo = m_decompiler->m_localVars[localVar];
					for (auto ctx : newExecCtxs)
						localVarInfo.m_execCtxs.insert(ctx);

					// add new register info
					neededRegs.push_back(registerInfo);
				}
			}

			// remove non-mutual registers from m_registers
			for (auto& regInfo : regs2) {
				delete regInfo.m_expr;
			}
			regs2.clear();

			// insert needed registers into m_registers
			regs2.insert(regs2.begin(), neededRegs.begin(), neededRegs.end());
		}
	}
}

std::list<RegisterExecContext::RegisterPart> RegisterExecContext::findRegisterParts(int regId, BitMask64& needReadMask) {
	std::list<RegisterInfo*> sameRegisters;

	//select same registeres
	auto it = m_registers.find(regId);
	if (it != m_registers.end()) {
		auto& registers = it->second;
		for (auto& regInfo : registers) {
			sameRegisters.push_back(&regInfo);
		}
	}

	//sort asc
	sameRegisters.sort([](RegisterInfo* a, RegisterInfo* b) {
		return a->m_register.m_valueRangeMask < b->m_register.m_valueRangeMask;
		});

	//gather need parts
	std::list<RegisterPart> regParts;
	for (auto sameRegInfo : sameRegisters) {
		auto sameRegExceptionMask = GetValueRangeMaskWithException(sameRegInfo->m_register); //for x86 only!!!
																							 //if the masks intersected
		if (!(needReadMask & sameRegExceptionMask).isZero()) {
			sameRegInfo->m_using = RegisterInfo::REGISTER_FULLY_USING;

			RegisterPart part;
			part.m_regMask = sameRegInfo->m_register.m_valueRangeMask;
			part.m_maskToChange = needReadMask & sameRegExceptionMask;
			part.m_expr = sameRegInfo->m_expr->getNode();
			regParts.push_back(part);
			needReadMask = needReadMask & ~sameRegExceptionMask;
		}

		if (needReadMask == 0)
			break;
	}

	return regParts;
}
