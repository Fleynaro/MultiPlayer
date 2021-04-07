#pragma once
#include "../../Graph/DecCodeGraphBlock.h"

namespace CE::Decompiler
{
	struct RegisterPart : public ExprTree::INodeAgregator {
		ExtBitMask m_regMask; // register range value mask
		ExtBitMask m_maskToChange; // that part of m_regMask where m_expr located
		ExprTree::INode* m_expr = nullptr;

		RegisterPart(ExtBitMask regMask, ExtBitMask maskToChange, ExprTree::INode* expr)
			: m_regMask(regMask), m_maskToChange(maskToChange), m_expr(expr)
		{
			m_expr->addParentNode(this);
		}

		~RegisterPart() {
			m_expr->removeBy(this);
		}

		void replaceNode(ExprTree::INode* node, ExprTree::INode* newNode) override {
			if (m_expr == node) {
				m_expr = newNode;
			}
		}

		std::list<ExprTree::INode*> getNodesList() override {
			return { m_expr };
		}
	};

	using RegisterParts = std::list<RegisterPart*>;

	static ExprTree::INode* CreateExprFromRegisterParts(RegisterParts regParts, ExtBitMask requestRegMask) {
		ExprTree::INode* resultExpr = nullptr;

		if (regParts.empty())
			throw std::logic_error("no register parts passed in");

		//descending sort
		regParts.sort([](const RegisterPart* a, const RegisterPart* b) {
			return b->m_regMask < a->m_regMask;
			});

		//in most cases bitRightShift = 0
		int bitRightShift = requestRegMask.getOffset();
		for (auto it : regParts) {
			auto& regPart = *it;
			auto regExpr = regPart.m_expr;
			int bitLeftShift = regPart.m_regMask.getOffset(); //e.g. if we requiest only AH,CH... registers.
			auto bitShift = bitRightShift - bitLeftShift;

			//regMask = 0xFFFFFFFF, maskToChange = 0xFFFF0000: expr(eax) | expr(ax) => (expr1 & 0xFFFF0000) | expr2
			if ((regPart.m_regMask & regPart.m_maskToChange) != regPart.m_regMask) {
				auto mask = (regPart.m_regMask & regPart.m_maskToChange) >> bitLeftShift;
				regExpr = new ExprTree::OperationalNode(regExpr, new ExprTree::NumberLeaf(mask.getBitMask64().getValue(), regExpr->getMask()), ExprTree::And/*, requestRegMaskForOpNode, true*/);
			}

			if (bitShift != 0) {
				regExpr = new ExprTree::OperationalNode(regExpr, new ExprTree::NumberLeaf((uint64_t)abs(bitShift), regExpr->getMask()), bitShift > 0 ? ExprTree::Shr : ExprTree::Shl/*, requestRegMaskForOpNode, true*/);
			}

			if (resultExpr) {
				resultExpr = new ExprTree::OperationalNode(resultExpr, regExpr, ExprTree::Or);
			}
			else {
				resultExpr = regExpr;
			}
		}
		return resultExpr;
	}

	class Decompiler; //todo: make interface later

	struct ExternalSymbol : public ExprTree::INodeAgregator {
		PCode::RegisterVarnode* m_regVarnode;
		RegisterParts m_regParts;
		ExtBitMask m_needReadMask;
		ExprTree::SymbolLeaf* m_symbolLeaf = nullptr;

		ExternalSymbol(PCode::RegisterVarnode* regVarnode, ExtBitMask needReadMask, ExprTree::SymbolLeaf* symbolLeaf, RegisterParts regParts)
			: m_regVarnode(regVarnode), m_needReadMask(needReadMask), m_symbolLeaf(symbolLeaf), m_regParts(regParts)
		{
			m_symbolLeaf->addParentNode(this);
		}

		~ExternalSymbol() {
			m_symbolLeaf->removeBy(this);
		}

		void replaceNode(ExprTree::INode* node, ExprTree::INode* newNode) override {
			
		}

		std::list<ExprTree::INode*> getNodesList() override {
			return { m_symbolLeaf };
		}
	};

	// execution interpreter context
	class ExecutionBlockContext
	{
	public:
		Decompiler* m_decompiler;

		struct VarnodeExpr {
			PCode::Varnode* m_varnode; // register/symbol varnode
			TopNode* m_expr;
			bool m_changed;
			
			VarnodeExpr(PCode::Varnode* varnode, TopNode* expr, bool changed)
				: m_varnode(varnode), m_expr(expr), m_changed(changed)
			{}
		};
		std::list<VarnodeExpr> m_varnodes;
		std::list<std::pair<PCode::Register, TopNode*>> m_cachedRegisters; // use of cache for optimization of addressing
		std::list<PCode::RegisterVarnode*> m_ownRegVarnodes;
		std::list<ExternalSymbol*> m_externalSymbols;
		std::set<PCode::RegisterVarnode*> m_resolvedExternalSymbols;

		ExecutionBlockContext(Decompiler* decompiler);

		// set expr. value to register
		void setVarnode(const PCode::Register& reg, ExprTree::INode* expr, bool rewrite = true);

		// set expr. value to varnode (register/symbol)
		void setVarnode(PCode::Varnode* varnode, ExprTree::INode* expr, bool rewrite = true);

		// try to get expr. values from register by {needReadMask} within this exec. block context (otherwise external symbol used)
		RegisterParts getRegisterParts(PCode::RegisterId registerId, ExtBitMask& needReadMask, bool changedRegistersOnly = false);

		// get expr. value from register varnode (this method uses getRegisterParts)
		ExprTree::INode* requestRegisterExpr(PCode::RegisterVarnode* varnodeRegister);

		// get expr. value from register (based on requestRegisterExpr for varnode)
		ExprTree::INode* requestRegisterExpr(const PCode::Register& reg);

		// get expr. value from symbol varnode
		ExprTree::INode* requestSymbolExpr(PCode::SymbolVarnode* symbolVarnode);
	};
};