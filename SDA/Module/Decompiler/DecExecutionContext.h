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

	struct ExternalSymbol : public ExprTree::IParentNode {
		Register m_reg;
		uint64_t m_needReadMask = 0x0;
		ExprTree::SymbolLeaf* m_symbol = nullptr;
		std::list<RegisterPart> m_regParts;

		ExternalSymbol(Register reg, uint64_t needReadMask, ExprTree::SymbolLeaf* symbol, std::list<RegisterPart> regParts)
			: m_reg(reg), m_needReadMask(needReadMask), m_symbol(symbol), m_regParts(regParts)
		{
			symbol->addParentNode(this);
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			
		}
	};

	class ExecutionBlockContext
	{
	public:
		int m_offset;
		Decompiler* m_decompiler;

		std::map<ZydisRegister, ExprTree::WrapperNode*> m_registers;
		std::map<ZydisRegister, ExprTree::WrapperNode*> m_cachedRegisters;
		std::map<ZydisCPUFlag, ExprTree::Condition*> m_flags;

		std::list<ExternalSymbol*> m_externalSymbols;

		struct {
			RegisterFlags flags = RegisterFlags::None;
			ExprTree::Node* leftNode = nullptr;
			ExprTree::Node* rightNode = nullptr;
		} m_lastCond;

		ExecutionBlockContext(Decompiler* decompiler, int startOffset = 0)
			: m_decompiler(decompiler), m_offset(startOffset)
		{}
		
		void setRegister(const Register& reg, ExprTree::Node* expr);

		std::list<RegisterPart> getRegisterParts(const Register& reg, uint64_t& mask);

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