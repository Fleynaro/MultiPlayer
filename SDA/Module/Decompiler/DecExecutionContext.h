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
		RegisterParts m_regParts;

		ExternalSymbol(Register reg, uint64_t needReadMask, ExprTree::SymbolLeaf* symbol, RegisterParts regParts)
			: m_reg(reg), m_needReadMask(needReadMask), m_symbol(symbol), m_regParts(regParts)
		{
			symbol->addParentNode(this);
		}

		~ExternalSymbol() {
			m_symbol->removeBy(this);
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			
		}
	};

	class ExecutionBlockContext : ExprTree::IParentNode
	{
	public:
		int m_offset;
		Decompiler* m_decompiler;

		std::map<ZydisRegister, ExprTree::Node*> m_registers;
		std::map<ZydisCPUFlag, ExprTree::Condition*> m_flags;

		class RegisterCache : public std::map<ZydisRegister, ExprTree::Node*>, public ExprTree::IParentNode
		{
		public:
			void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
				for (auto it = begin(); it != end(); it++) {
					if (it->second == node) {
						if (newNode != nullptr)
							it->second = newNode;
						else erase(it);
					}
				}
			}
		} m_cachedRegisters;

		std::list<ExternalSymbol*> m_externalSymbols;

		struct {
			RegisterFlags flags = RegisterFlags::None;
			ExprTree::Node* leftNode = nullptr;
			ExprTree::Node* rightNode = nullptr;
		} m_lastCond;

		ExecutionBlockContext(Decompiler* decompiler, int startOffset = 0)
			: m_decompiler(decompiler), m_offset(startOffset)
		{}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			for (auto it = m_registers.begin(); it != m_registers.end(); it ++) {
				if (it->second == node) {
					if (newNode != nullptr)
						it->second = newNode;
					else m_registers.erase(it);
				}
			}

			if (auto cond = dynamic_cast<ExprTree::Condition*>(node)) {	
				for (auto it = m_flags.begin(); it != m_flags.end(); it++) {
					if (it->second == cond) {
						if (auto newCond = dynamic_cast<ExprTree::Condition*>(newNode)) {
							it->second = newCond;
						}
						else {
							m_flags.erase(it);
						}
					}
				}
			}
		}
		
		void setRegister(const Register& reg, ExprTree::Node* expr);

		RegisterParts getRegisterParts(const Register& reg, uint64_t& mask);

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