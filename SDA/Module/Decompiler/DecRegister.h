#pragma once
#include "DecExecutionContext.h"

namespace CE::Decompiler
{
	class Register
	{
	public:
		struct RegInfo {
			uint64_t m_mask = 0x0;
			bool m_isVector = false;
			std::list<std::pair<ZydisRegister, uint64_t>> m_sameRegisters;
		};

		static RegInfo GetRegInfo(ZydisRegister reg) {
			RegInfo info;
			if (reg >= ZYDIS_REGISTER_AL && reg <= ZYDIS_REGISTER_BL) {
				info.m_mask = 0xFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_AL);
			}
			else if (reg >= ZYDIS_REGISTER_AH && reg <= ZYDIS_REGISTER_BH) {
				info.m_mask = 0xFF00;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_AH);
				info.m_sameRegisters.begin()->first = reg;
			}
			else if (reg >= ZYDIS_REGISTER_SPL && reg <= ZYDIS_REGISTER_R15B) {
				info.m_mask = 0xFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_AH);
			}
			else if (reg >= ZYDIS_REGISTER_AX && reg <= ZYDIS_REGISTER_R15W) {
				info.m_mask = 0xFFFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_AX);
			}
			else if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D) {
				info.m_mask = 0xFFFFFFFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_EAX);
			}
			else if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15) {
				info.m_mask = 0xFFFFFFFFFFFFFFFF;
				info.m_sameRegisters = GetListOfSameGenRegisters(reg - ZYDIS_REGISTER_RAX);
			}
			else if (reg >= ZYDIS_REGISTER_MM0 && reg <= ZYDIS_REGISTER_MM7) {
				info.m_mask = 0xF;
				info.m_isVector = true;
				info.m_sameRegisters = GetListOfSameVectorRegisters(reg - ZYDIS_REGISTER_MM0);
			}
			else if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31) {
				info.m_mask = 0xFF;
				info.m_isVector = true;
				info.m_sameRegisters = GetListOfSameVectorRegisters(reg - ZYDIS_REGISTER_XMM0);
			}
			else if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31) {
				info.m_mask = 0xFFFF;
				info.m_isVector = true;
				info.m_sameRegisters = GetListOfSameVectorRegisters(reg - ZYDIS_REGISTER_YMM0);
			}
			else if (reg >= ZYDIS_REGISTER_ZMM0 && reg <= ZYDIS_REGISTER_ZMM31) {
				info.m_mask = 0xFFFFFFFF;
				info.m_isVector = true;
				info.m_sameRegisters = GetListOfSameVectorRegisters(reg - ZYDIS_REGISTER_ZMM0);
			}
			else {
				info.m_mask = 0xFFFFFFFFFFFFFFFF;
			}
			return info;
		}

		static int GetRegisterParamIdx(ZydisRegister reg) {
			static std::set paramRegs_1 = {
				ZYDIS_REGISTER_CL,
				ZYDIS_REGISTER_CH,
				ZYDIS_REGISTER_CX,
				ZYDIS_REGISTER_ECX,
				ZYDIS_REGISTER_RCX,
				ZYDIS_REGISTER_XMM0,
				ZYDIS_REGISTER_YMM0,
				ZYDIS_REGISTER_ZMM0
			};
			static std::set paramRegs_2 = {
				ZYDIS_REGISTER_DL,
				ZYDIS_REGISTER_DH,
				ZYDIS_REGISTER_DX,
				ZYDIS_REGISTER_EDX,
				ZYDIS_REGISTER_RDX,
				ZYDIS_REGISTER_XMM1,
				ZYDIS_REGISTER_YMM1,
				ZYDIS_REGISTER_ZMM1
			};
			static std::set paramRegs_3 = {
				ZYDIS_REGISTER_R8B,
				ZYDIS_REGISTER_R8W,
				ZYDIS_REGISTER_R8D,
				ZYDIS_REGISTER_R8,
				ZYDIS_REGISTER_XMM2,
				ZYDIS_REGISTER_YMM2,
				ZYDIS_REGISTER_ZMM2
			};
			static std::set paramRegs_4 = {
				ZYDIS_REGISTER_R9B,
				ZYDIS_REGISTER_R9W,
				ZYDIS_REGISTER_R9D,
				ZYDIS_REGISTER_R9,
				ZYDIS_REGISTER_XMM3,
				ZYDIS_REGISTER_YMM3,
				ZYDIS_REGISTER_ZMM3
			};

			if (paramRegs_1.find(reg) != paramRegs_1.end()) {
				return 1;
			}

			if (paramRegs_2.find(reg) != paramRegs_2.end()) {
				return 2;
			}

			if (paramRegs_3.find(reg) != paramRegs_3.end()) {
				return 3;
			}

			if (paramRegs_4.find(reg) != paramRegs_4.end()) {
				return 4;
			}

			return 0;
		}

		static int GetShiftValueOfMask(uint64_t mask) {
			int result = 0;
			for (auto m = mask; int(m & 0xF) == 0; m = m >> 4) {
				result += 4;
			}
			return result;
		}

		static ExprTree::Node* CreateExprRegLeaf(ExecutionContext* ctx, ZydisRegister reg) {
			Symbol::Symbol* symbol = new Symbol::LocalRegVar(reg);
			auto leaf = new ExprTree::SymbolLeaf(symbol);
			return leaf;
		}

		static ExprTree::Node* GetOrCreateExprRegLeaf(ExecutionContext* ctx, ZydisRegister reg) {
			if (ctx->m_registers.find(reg) != ctx->m_registers.end()) {
				return ctx->m_registers[reg];
			}

			auto regInfo = Register::GetRegInfo(reg);
			ExprTree::Node* node = nullptr;
			for (auto it = regInfo.m_sameRegisters.rbegin(); it != regInfo.m_sameRegisters.rend(); it++) {
				auto sameReg = *it;
				if (sameReg.first != reg) {
					auto it = ctx->m_registers.find(sameReg.first);
					if (it != ctx->m_registers.end()) {
						node = it->second;
						if (sameReg.second > regInfo.m_mask) {
							node = new ExprTree::OperationalNode(node, new ExprTree::NumberLeaf(sameReg.second & regInfo.m_mask), ExprTree::And);
							int rightBitShift = Register::GetShiftValueOfMask(regInfo.m_mask);
							if (rightBitShift != 0) {
								node = new ExprTree::OperationalNode(node, new ExprTree::NumberLeaf(rightBitShift), ExprTree::Shr);
							}
						}
						break;
					}
				}
			}

			if (!node) {
				node = CreateExprRegLeaf(ctx, reg);
			}
			ctx->m_registers.insert(std::make_pair(reg, node));
			return node;
		}

	private:
		static std::list<std::pair<ZydisRegister, uint64_t>> GetListOfSameGenRegisters(int idx) {
			std::list result = {
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_AX + idx), (uint64_t)0xFFFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_EAX + idx), (uint64_t)0xFFFFFFFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_RAX + idx), (uint64_t)0xFFFFFFFFFFFFFFFF)
			};
			if (idx <= 3)
				result.push_front(std::make_pair(ZydisRegister(ZYDIS_REGISTER_AL + idx), (uint64_t)0xFF));
			else result.push_front(std::make_pair(ZydisRegister(ZYDIS_REGISTER_AH + idx), (uint64_t)0xFF));
			return result;
		}

		static std::list<std::pair<ZydisRegister, uint64_t>> GetListOfSameVectorRegisters(int idx) {
			std::list result = {
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_XMM0 + idx), (uint64_t)0xFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_YMM0 + idx), (uint64_t)0xFFFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_ZMM0 + idx), (uint64_t)0xFFFFFFFF)
			};
			if (idx <= 7)
				result.push_front(std::make_pair(ZydisRegister(ZYDIS_REGISTER_MM0 + idx), (uint64_t)0xF));
			return result;
		}
	};
};