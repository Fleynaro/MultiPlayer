#pragma once
#include "DecRegister.h"

namespace CE::Decompiler
{
	enum class RegisterFlags {
		None,
		CF = 1 << 1,
		PF = 1 << 2,
		AF = 1 << 3,
		ZF = 1 << 4,
		SF = 1 << 5,
		OF = 1 << 6,

		TEST = ZF | SF | PF,
		CMP = TEST | CF | OF
	};

	class Decompiler; //make interface later

	struct ExecutionBlockContextData {

	};

	struct RegisterPart {
		uint64_t regMask = -1;
		uint64_t maskToChange = -1;
		ExprTree::Node* expr = nullptr;
	};

	class ExecutionBlockContext
	{
	public:
		int m_offset;
		Decompiler* m_decompiler;

		std::map<ZydisRegister, ExprTree::Node*> m_registers;
		std::map<ZydisRegister, ExprTree::Node*> m_cachedRegisters;
		std::map<ZydisCPUFlag, ExprTree::Condition*> m_flags;

		struct {
			RegisterFlags flags = RegisterFlags::None;
			ExprTree::Node* leftNode = nullptr;
			ExprTree::Node* rightNode = nullptr;
		} m_lastCond;

		ExecutionBlockContext(Decompiler* decompiler, int startOffset = 0)
			: m_decompiler(decompiler), m_offset(startOffset)
		{}
		
		void setRegister(const Register& reg, ExprTree::Node* expr);

		std::list<RegisterPart> getRegisterParts(const Register& reg, uint64_t& mask) {
			std::list<RegisterPart> regParts;
			for (auto sameReg : reg.m_sameRegisters) {
				auto reg = sameReg.first;
				auto it = m_registers.find(reg);
				if (it != m_registers.end()) {
					auto sameRegMask = sameReg.second;
					auto changedRegMask = mask & ~sameRegMask;
					if (changedRegMask != mask) {
						RegisterPart info;
						info.regMask = sameRegMask;
						info.maskToChange = mask & sameRegMask;
						info.expr = it->second;
						regParts.push_back(info);
						mask = changedRegMask;
					}
				}

				if (mask == 0)
					break;
			}
			return regParts;
		}

		ExprTree::Node* requestRegister(const Register& reg);

		void setLastCond(ExprTree::Node* leftNode, ExprTree::Node* rightNode, RegisterFlags flags) {
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

		void clearLastCond() {
			setLastCond(nullptr, nullptr, RegisterFlags::None);
		}
	};
};