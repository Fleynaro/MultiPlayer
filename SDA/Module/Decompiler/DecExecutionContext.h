#pragma once
#include "DecPCode.h"
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
	};
};