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

		static int GetShiftValueOfMask(uint64_t mask) {
			int result = 0;
			for (auto m = mask; int(m & 0xF) == 0; m = m >> 4) {
				result += 4;
			}
			return result;
		}

		static int GetBitCountOfMask(uint64_t mask) {
			int result = 0;
			for (auto m = mask; m != 0; m = m >> 1) {
				result ++;
			}
			return result;
		}

		static ExprTree::Node* CreateExprRegLeaf(ExecutionBlockContext* ctx, ZydisRegister reg) {
			Symbol::Symbol* symbol = new Symbol::LocalRegVar(reg);
			auto leaf = new ExprTree::SymbolLeaf(symbol);
			return leaf;
		}

		//MYTODO: запрашиваем eax регистр, но получаем старый перезаписанный eax регистр, а не новый rax
		static ExprTree::Node* GetOrCreateExprRegLeaf(ExecutionBlockContext* ctx, ZydisRegister reg) {
			auto regExpr = ctx->getRegister(reg);
			if (regExpr != nullptr) {
				return GetRegisterExpr(ctx, reg, regExpr);
			}

			//find the most suitable register
			auto regInfo = Register::GetRegInfo(reg);
			struct {
				uint64_t mask = -1;
				ZydisRegister reg = ZYDIS_REGISTER_NONE;
				ExprTree::Node* expr = nullptr;
			} suitSameReg;

			int minBitsCount = 64;
			for (auto sameRegIt = regInfo.m_sameRegisters.begin(); sameRegIt != regInfo.m_sameRegisters.end(); sameRegIt++) {
				if (sameRegIt->first == reg)
					continue;
				auto reg = sameRegIt->first;
				auto regExpr = ctx->getRegister(reg);
				if (regExpr != nullptr) {
					auto mask = sameRegIt->second & regInfo.m_mask;
					auto bitsCount = GetBitCountOfMask(mask);
					if (bitsCount < minBitsCount) {
						suitSameReg.mask = mask;
						suitSameReg.reg = reg;
						suitSameReg.expr = regExpr;
						minBitsCount = bitsCount;
					}
				}
			}

			ExprTree::Node* node = nullptr;
			if (suitSameReg.mask != -1) {
				//if that register found
				node = GetRegisterExpr(ctx, suitSameReg.reg, suitSameReg.expr);
				node = new ExprTree::OperationalNode(node, new ExprTree::NumberLeaf(suitSameReg.mask), ExprTree::And);
				int rightBitShift = GetShiftValueOfMask(regInfo.m_mask);
				if (rightBitShift != 0) {
					node = new ExprTree::OperationalNode(node, new ExprTree::NumberLeaf(rightBitShift), ExprTree::Shr);
				}
			}

			if (!node) {
				node = CreateExprRegLeaf(ctx, reg);
			}
			ctx->setRegister(reg, node);
			return node;
		}

	private:
		static ExprTree::Node* GetRegisterExpr(ExecutionBlockContext* ctx, ZydisRegister reg, ExprTree::Node* regExpr) {
			auto regInfo = Register::GetRegInfo(reg);
			uint64_t mask = regInfo.m_mask;
			std::list<std::pair<uint64_t, std::pair<ZydisRegister, ExprTree::Node*>>> sameRegisters;

			for (auto sameReg : regInfo.m_sameRegisters) {
				if (sameReg.first == reg)
					continue;
				auto reg = sameReg.first;
				auto regExpr = ctx->getRegister(reg);
				if (regExpr != nullptr) {
					if (regInfo.m_mask > sameReg.second) {
						mask &= ~sameReg.second;
						sameRegisters.push_back(std::make_pair(sameReg.second, std::make_pair(reg, regExpr)));
					}
				}
			}

			if (mask != regInfo.m_mask) {
				regExpr = new ExprTree::OperationalNode(regExpr, new ExprTree::NumberLeaf(mask), ExprTree::And); //[reg_edx] & 0xffffffff00000000 (sample8)
				for (auto sameReg : sameRegisters) {
					if (sameReg.first != 0) {
						auto sameRegExpr = sameReg.second.second;
						int leftBitShift = Register::GetShiftValueOfMask(sameReg.first);
						if (leftBitShift != 0) {
							sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(leftBitShift), ExprTree::Shl);
						}
						auto maskNumber = new ExprTree::NumberLeaf(sameReg.first & regInfo.m_mask); //for signed register operations and etc...
						sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, maskNumber, ExprTree::And);
						regExpr = new ExprTree::OperationalNode(regExpr, sameRegExpr, ExprTree::Or);
					}
				}
			}
			return regExpr;
		}

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