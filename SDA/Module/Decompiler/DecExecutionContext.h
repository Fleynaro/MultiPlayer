#pragma once
#include "DecPCode.h"
#include "PrimaryTree/PrimaryTreeBlock.h"

namespace CE::Decompiler
{
	struct RegisterPart : public ExprTree::INodeAgregator {
		ExtBitMask m_regMask;
		ExtBitMask m_maskToChange;
		ExprTree::Node* m_expr = nullptr;

		RegisterPart(ExtBitMask regMask, ExtBitMask maskToChange, ExprTree::Node* expr)
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

		std::list<ExprTree::Node**> getNodePtrsList() override {
			return { &m_expr };
		}
	};

	using RegisterParts = std::list<RegisterPart*>;

	static ExprTree::Node* CreateExprFromRegisterParts(RegisterParts regParts, ExtBitMask requestRegMask) {
		ExprTree::Node* resultExpr = nullptr;

		regParts.sort([](const RegisterPart* a, const RegisterPart* b) {
			return b->m_regMask < a->m_regMask;
			});

		int bitRightShift = requestRegMask.getOffset();
		for (auto it : regParts) {
			auto& regPart = *it;
			auto sameRegExpr = regPart.m_expr;
			int bitLeftShift = regPart.m_regMask.getOffset(); //e.g. if we requiest only AH,CH... registers.
			auto bitShift = bitRightShift - bitLeftShift;

			if ((regPart.m_regMask & regPart.m_maskToChange) != regPart.m_regMask) {
				auto mask = (regPart.m_regMask & regPart.m_maskToChange) >> bitLeftShift;
				sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(mask.getBitMask64().getValue()), ExprTree::And/*, requestRegMaskForOpNode, true*/);
			}

			if (bitShift != 0) {
				sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf((uint64_t)abs(bitShift)), bitShift > 0 ? ExprTree::Shr : ExprTree::Shl/*, requestRegMaskForOpNode, true*/);
			}

			if (resultExpr) {
				resultExpr = new ExprTree::OperationalNode(resultExpr, sameRegExpr, ExprTree::Or);
			}
			else {
				resultExpr = sameRegExpr;
			}
		}
		return resultExpr;
	}

	class Decompiler; //make interface later

	struct ExternalSymbol : public ExprTree::INodeAgregator {
		PCode::RegisterVarnode* m_regVarnode;
		RegisterParts m_regParts;
		ExtBitMask m_needReadMask;
		ExprTree::SymbolLeaf* m_symbol = nullptr;

		ExternalSymbol(PCode::RegisterVarnode* regVarnode, ExtBitMask needReadMask, ExprTree::SymbolLeaf* symbol, RegisterParts regParts)
			: m_regVarnode(regVarnode), m_needReadMask(needReadMask), m_symbol(symbol), m_regParts(regParts)
		{
			symbol->addParentNode(this);
		}

		~ExternalSymbol() {
			m_symbol->removeBy(this);
		}

		void replaceNode(ExprTree::Node* node, ExprTree::Node* newNode) override {
			
		}

		std::list<ExprTree::Node**> getNodePtrsList() override {
			return { (ExprTree::Node**)&m_symbol };
		}
	};

	class ExecutionBlockContext
	{
	public:
		Decompiler* m_decompiler;

		template<typename T = ExprTree::Node>
		class WrapperNode : public ExprTree::INodeAgregator
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

			std::list<ExprTree::Node**> getNodePtrsList() override {
				return { (ExprTree::Node**)&m_node };
			}
		};

		struct VarnodeExpr {
			PCode::Varnode* m_varnode;
			WrapperNode<ExprTree::Node>* m_expr;
			bool m_changed;
			
			VarnodeExpr(PCode::Varnode* varnode, WrapperNode<ExprTree::Node>* expr, bool changed)
				: m_varnode(varnode), m_expr(expr), m_changed(changed)
			{}
		};
		std::list<VarnodeExpr> m_varnodes;
		std::list<std::pair<PCode::Register, WrapperNode<ExprTree::Node>*>> m_cachedRegisters;
		std::list<PCode::RegisterVarnode*> m_ownRegVarnodes;
		std::list<ExternalSymbol*> m_externalSymbols;
		std::set<PCode::RegisterVarnode*> m_resolvedExternalSymbols;

		ExecutionBlockContext(Decompiler* decompiler);

		void setVarnode(const PCode::Register& reg, ExprTree::Node* expr, bool rewrite = true);

		void setVarnode(PCode::Varnode* varnode, ExprTree::Node* expr, bool rewrite = true);

		RegisterParts getRegisterParts(PCode::RegisterId registerId, ExtBitMask& mask, bool changedRegistersOnly = false);

		ExprTree::Node* requestRegisterExpr(PCode::RegisterVarnode* varnodeRegister);

		ExprTree::Node* requestRegisterExpr(const PCode::Register& reg);

		ExprTree::Node* requestSymbolExpr(PCode::SymbolVarnode* symbolVarnode);
	};
};