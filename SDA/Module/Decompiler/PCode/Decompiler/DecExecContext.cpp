#include "DecExecContext.h"
#include "Decompiler.h"

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
				auto mask1 = calculateMaxMask(regs1);
				auto mask2 = calculateMaxMask(regs2);
				auto resultMask = mask1 & mask2;

				// new register
				auto& sampleReg = regs1.begin()->m_register;
				auto newRegister = Register(sampleReg.getGenericId(), sampleReg.getIndex(), resultMask, sampleReg.getType());;

				// new local var and register info
				RegisterInfo registerInfo;
				registerInfo.m_register = newRegister;
				auto symbol = new Symbol::LocalVariable(resultMask);
				registerInfo.m_expr = new TopNode(new ExprTree::SymbolLeaf(symbol));
				registerInfo.m_srcExecContext = m_execContext;
				registerInfo.m_hasParAssginmentCreated = true;

				// local var info for par. assignments
				Decompiler::LocalVarInfo localVarInfo;
				localVarInfo.m_register = newRegister;
				for (auto& regs : { regs1, regs2 }) {
					for (auto& regInfo : regs) {
						localVarInfo.m_execCtxs.push_back(regInfo.m_srcExecContext);
					}
				}
				m_decompiler->m_localVars[symbol] = localVarInfo;

				neededRegs.push_back(registerInfo);
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
			RegisterPart part;
			part.m_regMask = sameRegInfo->m_register.m_valueRangeMask;
			part.m_maskToChange = needReadMask & sameRegExceptionMask;
			part.m_expr = sameRegInfo->m_expr->getNode();
			regParts.push_back(part);

			// if this register containts a local var symbol
			if (sameRegInfo->m_hasParAssginmentCreated) {
				if (auto localVarLeaf = dynamic_cast<ExprTree::SymbolLeaf*>(sameRegInfo->m_expr->getNode())) {
					if (auto localVar = dynamic_cast<Symbol::LocalVariable*>(localVarLeaf->m_symbol)) {
						auto it = m_decompiler->m_localVars.find(localVar);
						if (it != m_decompiler->m_localVars.end()) {
							// iterate over all ctxs and create assignments: localVar1 = 0x5
							auto& localVarInfo = it->second;
							for (auto execCtx : localVarInfo.m_execCtxs) {
								auto expr = execCtx->m_registerExecCtx.requestRegister(localVarInfo.m_register);

								auto& blockInfo = m_decompiler->m_decompiledBlocks[execCtx->m_pcodeBlock];
								blockInfo.m_decBlock->addSymbolParallelAssignmentLine(localVarLeaf, expr);
							}

							m_decompiler->m_decompiledGraph->addSymbol(localVar);
							m_decompiler->m_localVars.erase(it);
						}
					}
				}
				sameRegInfo->m_hasParAssginmentCreated = false;
			}

			needReadMask = needReadMask & ~sameRegExceptionMask;
		}

		if (needReadMask == 0)
			break;
	}

	return regParts;
}
