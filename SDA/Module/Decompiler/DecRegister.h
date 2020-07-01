#pragma once
#include "PrimaryTree/PrimaryTreeBlock.h"

namespace CE::Decompiler
{
	struct RegisterPart : public ExprTree::IParentNode {
		uint64_t m_regMask = -1;
		uint64_t m_maskToChange = -1;
		ExprTree::Node* m_expr = nullptr;

		RegisterPart(uint64_t regMask, uint64_t maskToChange, ExprTree::Node* expr)
			: m_regMask(regMask), m_maskToChange(maskToChange), m_expr(expr)
		{
			m_expr->addParentNode(this);
		}

		~RegisterPart() {
			m_expr->removeBy(this);
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			if (m_expr == node) {
				m_expr = newNode;
			}
		}
	};

	using RegisterParts = std::list<RegisterPart*>;

	class Register
	{
	public:
		ZydisRegister m_reg;
		uint64_t m_mask = 0x0;
		bool m_isVector = false;
		std::list<std::pair<ZydisRegister, uint64_t>> m_sameRegisters;

		Register(ZydisRegister reg)
			: m_reg(reg)
		{
			GetRegInfo();
		}

		int getId() const {
			return m_sameRegisters.begin()->first;
		}

		int getSize() const {
			return GetBitCountOfMask(m_mask) / 8;
		}

		static ExprTree::Node* CreateExprFromRegisterParts(RegisterParts regParts, uint64_t requestRegMask) {
			ExprTree::Node* resultExpr = nullptr;

			regParts.sort([](const RegisterPart* a, const RegisterPart* b) {
				return a->m_regMask > b->m_regMask;
				});

			for (auto it : regParts) {
				auto& regPart = *it;
				auto sameRegExpr = regPart.m_expr;
				int bitShift = GetShiftValueOfMask(regPart.m_regMask | ~requestRegMask); //e.g. if we requiest only AH,CH... registers.

				if (regPart.m_regMask != requestRegMask) {
					//for signed register operations and etc...
					sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf((regPart.m_regMask & requestRegMask) >> bitShift), ExprTree::And);
				}

				if (bitShift != 0) {
					sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(bitShift), ExprTree::Shl);
				}

				if (resultExpr) {
					resultExpr = new ExprTree::OperationalNode(resultExpr, new ExprTree::NumberLeaf(~regPart.m_maskToChange), ExprTree::And);
					resultExpr = new ExprTree::OperationalNode(resultExpr, sameRegExpr, ExprTree::Or);
				}
				else {
					resultExpr = sameRegExpr;
				}
			}
			return resultExpr;
		}
	private:
		void GetRegInfo() {
			if (m_reg >= ZYDIS_REGISTER_AL && m_reg <= ZYDIS_REGISTER_BL) {
				m_mask = 0xFF;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_AL);
			}
			else if (m_reg >= ZYDIS_REGISTER_AH && m_reg <= ZYDIS_REGISTER_BH) {
				m_mask = 0xFF00;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_AH);
			}
			else if (m_reg >= ZYDIS_REGISTER_SPL && m_reg <= ZYDIS_REGISTER_R15B) {
				m_mask = 0xFF;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_AH);
			}
			else if (m_reg >= ZYDIS_REGISTER_AX && m_reg <= ZYDIS_REGISTER_R15W) {
				m_mask = 0xFFFF;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_AX);
			}
			else if (m_reg >= ZYDIS_REGISTER_EAX && m_reg <= ZYDIS_REGISTER_R15D) {
				m_mask = 0xFFFFFFFFFFFFFFFF; //exception: eax(no ax, ah, al!) overwrite rax!!!
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_EAX);
			}
			else if (m_reg >= ZYDIS_REGISTER_RAX && m_reg <= ZYDIS_REGISTER_R15) {
				m_mask = 0xFFFFFFFFFFFFFFFF;
				m_sameRegisters = GetListOfSameGenRegisters(m_reg - ZYDIS_REGISTER_RAX);
			}
			else if (m_reg >= ZYDIS_REGISTER_MM0 && m_reg <= ZYDIS_REGISTER_MM7) {
				m_mask = 0xF;
				m_isVector = true;
				m_sameRegisters = GetListOfSameVectorRegisters(m_reg - ZYDIS_REGISTER_MM0);
			}
			else if (m_reg >= ZYDIS_REGISTER_XMM0 && m_reg <= ZYDIS_REGISTER_XMM31) {
				m_mask = 0xFF;
				m_isVector = true;
				m_sameRegisters = GetListOfSameVectorRegisters(m_reg - ZYDIS_REGISTER_XMM0);
			}
			else if (m_reg >= ZYDIS_REGISTER_YMM0 && m_reg <= ZYDIS_REGISTER_YMM31) {
				m_mask = 0xFFFF;
				m_isVector = true;
				m_sameRegisters = GetListOfSameVectorRegisters(m_reg - ZYDIS_REGISTER_YMM0);
			}
			else if (m_reg >= ZYDIS_REGISTER_ZMM0 && m_reg <= ZYDIS_REGISTER_ZMM31) {
				m_mask = 0xFFFFFFFF;
				m_isVector = true;
				m_sameRegisters = GetListOfSameVectorRegisters(m_reg - ZYDIS_REGISTER_ZMM0);
			}
			else {
				m_mask = 0xFFFFFFFFFFFFFFFF;
			}
		}

		static std::list<std::pair<ZydisRegister, uint64_t>> GetListOfSameGenRegisters(int idx) {
			std::list result = {
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_AH + idx), (uint64_t)0xFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_AX + idx), (uint64_t)0xFFFF),
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_EAX + idx), (uint64_t)0xFFFFFFFFFFFFFFFF), //exception: eax(no ax, ah, al!) overwrite rax!!!
				std::make_pair(ZydisRegister(ZYDIS_REGISTER_RAX + idx), (uint64_t)0xFFFFFFFFFFFFFFFF)
			};
			if (idx <= 3) {
				result.begin()->second <<= 8;
				result.push_front(std::make_pair(ZydisRegister(ZYDIS_REGISTER_AL + idx), (uint64_t)0xFF));
			}
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