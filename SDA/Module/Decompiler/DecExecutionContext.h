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

	class ExecutionBlockContext
	{
	public:
		int m_offset;
		Decompiler* m_decompiler;

		template<typename T = ExprTree::Node>
		class WrapperNode : public ExprTree::IParentNode
		{
		public:
			T* m_node;
			WrapperNode(T* node)
				: m_node(node)
			{
				node->addParentNode(this);
			}

			~WrapperNode() {
				if (m_node) {
					m_node->removeBy(this);
				}
			}

			void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
				if (m_node == node) {
					m_node = static_cast<T*>(newNode);
				}
			}
		};

		std::map<ZydisRegister, WrapperNode<ExprTree::Node>*> m_registers;
		std::map<ZydisRegister, WrapperNode<ExprTree::Node>*> m_cachedRegisters;
		std::map<ZydisCPUFlag, WrapperNode<ExprTree::Condition>*> m_flags;
		std::set<ZydisRegister> m_changedRegisters;
		std::list<ExternalSymbol*> m_externalSymbols;

		struct {
			RegisterFlags flags = RegisterFlags::None;
			ExprTree::Node* leftNode = nullptr;
			ExprTree::Node* rightNode = nullptr;
		} m_lastCond;

		ExecutionBlockContext(Decompiler* decompiler, int startOffset = 0);

		void setRegister(const Register& reg, ExprTree::Node* expr, bool rewrite = true);

		RegisterParts getRegisterParts(const Register& reg, uint64_t& mask, bool changedRegistersOnly = false);

		ExprTree::Node* requestRegister(const Register& reg);

		ExprTree::Condition* getFlag(ZydisCPUFlag flag);

		void setFlag(ZydisCPUFlag flag, ExprTree::Condition* cond);

		void setLastCond(ExprTree::Node* leftNode, ExprTree::Node* rightNode, RegisterFlags flags);

		void clearLastCond();
	};
};