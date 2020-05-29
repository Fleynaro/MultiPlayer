#pragma once
#include "PrimaryTree/PrimaryTreeBlock.h"

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

	class ExecutionContext
	{
	public:
		int m_offset;
		Decompiler* m_decompiler;

		std::map<ZydisRegister, ExprTree::Node*> m_registers;
		std::map<ZydisCPUFlag, ExprTree::Condition*> m_flags;

		struct {
			RegisterFlags flags = RegisterFlags::None;
			ExprTree::Node* leftNode = nullptr;
			ExprTree::Node* rightNode = nullptr;
		} m_lastCond;

		ExecutionContext(Decompiler* decompiler, int startOffset = 0)
			: m_decompiler(decompiler), m_offset(startOffset)
		{}

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