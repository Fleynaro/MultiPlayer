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

	static ExprTree::Node* CreateExprFromRegisterParts(RegisterParts regParts, uint64_t requestRegMask, bool isVector) {
		ExprTree::Node* resultExpr = nullptr;

		regParts.sort([](const RegisterPart* a, const RegisterPart* b) {
			return a->m_regMask > b->m_regMask;
			});

		/*Mask requestRegMaskForOpNode;
		if (isVector) {
			requestRegMaskForOpNode = requestRegMask;
		} else {
			requestRegMaskForOpNode = GetMaskByMask64(requestRegMask);
		}*/

		for (auto it : regParts) {
			auto& regPart = *it;
			auto sameRegExpr = regPart.m_expr;
			int bitShift = GetShiftValueOfMask(regPart.m_regMask | ~requestRegMask); //e.g. if we requiest only AH,CH... registers.

			//see if is regPart.m_regMask bigger than requestRegMask
			if ((regPart.m_regMask & ~requestRegMask) != 0x0) {
				auto mask = (regPart.m_regMask & requestRegMask) >> bitShift;
				if (isVector) mask = GetMask64ByMask(mask);
				//for operations and etc...
				sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf(mask), ExprTree::And/*, requestRegMaskForOpNode, true*/);
			}

			if (bitShift != 0) {
				auto bitShift_ = bitShift;
				if (isVector) bitShift_ *= 8;
				sameRegExpr = new ExprTree::OperationalNode(sameRegExpr, new ExprTree::NumberLeaf((uint64_t)bitShift_), ExprTree::Shl/*, requestRegMaskForOpNode, true*/);
			}

			if (resultExpr) {
				auto mask = ~regPart.m_maskToChange;
				if (isVector) mask = GetMask64ByMask(mask);
				resultExpr = new ExprTree::OperationalNode(resultExpr, new ExprTree::NumberLeaf(mask), ExprTree::And/*, requestRegMaskForOpNode, true*/);
				resultExpr = new ExprTree::OperationalNode(resultExpr, sameRegExpr, ExprTree::Or);
			}
			else {
				resultExpr = sameRegExpr;
			}
		}
		return resultExpr;
	}

	class Decompiler; //make interface later

	struct ExternalSymbol : public ExprTree::IParentNode {
		PCode::Register m_reg;
		RegisterParts m_regParts;
		uint64_t m_needReadMask = 0x0;
		ExprTree::SymbolLeaf* m_symbol = nullptr;

		ExternalSymbol(PCode::Register reg, uint64_t needReadMask, ExprTree::SymbolLeaf* symbol, RegisterParts regParts)
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

		ExecutionBlockContext(Decompiler* decompiler);

		void setVarnode(const PCode::Register& reg, ExprTree::Node* expr, bool rewrite = true);

		void setVarnode(PCode::Varnode* varnode, ExprTree::Node* expr, bool rewrite = true);

		RegisterParts getRegisterParts(const PCode::Register& reg, uint64_t& mask, bool changedRegistersOnly = false);

		ExprTree::Node* requestRegisterExpr(PCode::RegisterVarnode* varnodeRegister);

		ExprTree::Node* requestRegisterExpr(const PCode::Register& reg);

		ExprTree::Node* requestSymbolExpr(PCode::SymbolVarnode* symbolVarnode);
	};
};