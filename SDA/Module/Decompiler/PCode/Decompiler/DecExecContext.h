#pragma once
#include <Decompiler/Graph/DecCodeGraph.h>

namespace CE::Decompiler
{
	class Decompiler;
	class ExecContext;

	struct RegisterExecContext
	{
		struct RegisterInfo {
			PCode::Register m_register;
			TopNode* m_expr;
			ExecContext* m_srcExecContext;
			bool m_hasParAssginmentCreated = false;
		};

		struct RegisterPart {
			BitMask64 m_regMask; // register range value mask
			BitMask64 m_maskToChange; // that part of m_regMask where m_expr located
			ExprTree::INode* m_expr = nullptr;
		};

		Decompiler* m_decompiler;
		std::map<PCode::RegisterId, std::list<RegisterInfo>> m_registers;
		ExecContext* m_execContext;
		bool m_isFilled = false;

		RegisterExecContext(Decompiler* decompiler, ExecContext* execContext)
			: m_decompiler(decompiler), m_execContext(execContext)
		{}

		ExprTree::INode* requestRegister(const PCode::Register& reg);

		void setRegister(const PCode::Register& reg, ExprTree::INode* newExpr) {
			std::list<TopNode*> oldTopNodes;

			auto it = m_registers.find(reg.getId());
			if (it != m_registers.end()) {
				auto& registers = it->second;
				// write rax -> remove eax/ax/ah/al
				for (auto it2 = registers.begin(); it2 != registers.end(); it2++) {
					if (reg.intersect(it2->m_register)) {
						oldTopNodes.push_back(it2->m_expr);
						m_registers.erase(it);
					}
				}
			}
			else {
				m_registers[reg.getId()] = std::list<RegisterInfo>();
			}

			// add the register
			RegisterInfo registerInfo;
			registerInfo.m_register = reg;
			registerInfo.m_expr = new TopNode(newExpr);
			registerInfo.m_srcExecContext = m_execContext;
			m_registers[reg.getId()].push_back(registerInfo);

			// delete only here because new expr may be the same as old expr: mov rax, rax
			for (auto topNode : oldTopNodes) {
				delete topNode;
			}
		}

		void copyFrom(RegisterExecContext* ctx);

		void join(RegisterExecContext* ctx);

	private:
		std::list<RegisterPart> findRegisterParts(int regId, BitMask64& needReadMask);

		BitMask64 calculateMaxMask(const std::list<RegisterInfo>& regs) {
			BitMask64 mask;
			for (auto reg : regs) {
				mask = mask | reg.m_register.m_valueRangeMask;
			}
			return mask;
		}

		static ExprTree::INode* CreateExprFromRegisterParts(std::list<RegisterPart> regParts, BitMask64 requestRegMask) {
			ExprTree::INode* resultExpr = nullptr;

			//descending sort
			regParts.sort([](RegisterPart& a, RegisterPart& b) {
				return b.m_regMask < a.m_regMask;
				});

			//in most cases bitRightShift = 0
			int bitRightShift = requestRegMask.getOffset();
			for (auto& regPart : regParts) {
				auto regExpr = regPart.m_expr;
				int bitLeftShift = regPart.m_regMask.getOffset(); //e.g. if we requiest only AH,CH... registers.
				auto bitShift = bitRightShift - bitLeftShift;

				//regMask = 0xFFFFFFFF, maskToChange = 0xFFFF0000: expr(eax) | expr(ax) => (expr1 & 0xFFFF0000) | expr2
				if ((regPart.m_regMask & regPart.m_maskToChange) != regPart.m_regMask) {
					auto mask = (regPart.m_regMask & regPart.m_maskToChange) >> bitLeftShift;
					regExpr = new ExprTree::OperationalNode(regExpr, new ExprTree::NumberLeaf(mask.getValue(), regExpr->getMask()), ExprTree::And);
				}

				if (bitShift != 0) {
					regExpr = new ExprTree::OperationalNode(regExpr, new ExprTree::NumberLeaf((uint64_t)abs(bitShift), regExpr->getMask()), bitShift > 0 ? ExprTree::Shr : ExprTree::Shl);
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
	};

	class ExecContext
	{
		std::map<PCode::SymbolVarnode*, TopNode*> m_symbolVarnodes;
	public:
		RegisterExecContext m_startRegisterExecCtx;
		RegisterExecContext m_registerExecCtx;
		PCodeBlock* m_pcodeBlock;

		ExecContext(Decompiler* decompiler, PCodeBlock* pcodeBlock)
			: m_startRegisterExecCtx(decompiler, this), m_registerExecCtx(m_startRegisterExecCtx), m_pcodeBlock(pcodeBlock)
		{}

		ExprTree::INode* requestVarnode(PCode::Varnode* varnode) {
			if (auto registerVarnode = dynamic_cast<PCode::RegisterVarnode*>(varnode)) {
				return m_registerExecCtx.requestRegister(registerVarnode->m_register);
			}
			if (auto symbolVarnode = dynamic_cast<PCode::SymbolVarnode*>(varnode)) {
				auto it = m_symbolVarnodes.find(symbolVarnode);
				if (it != m_symbolVarnodes.end()) {
					auto topNode = it->second;
					return topNode->getNode();
				}
			}
			if (auto varnodeConstant = dynamic_cast<PCode::ConstantVarnode*>(varnode)) {
				return new ExprTree::NumberLeaf(varnodeConstant->m_value, varnodeConstant->getMask());
			}
			return nullptr;
		}

		void setVarnode(PCode::Varnode* varnode, ExprTree::INode* newExpr) {
			if (auto registerVarnode = dynamic_cast<PCode::RegisterVarnode*>(varnode)) {
				m_registerExecCtx.setRegister(registerVarnode->m_register, newExpr);
			}
			if (auto symbolVarnode = dynamic_cast<PCode::SymbolVarnode*>(varnode)) {
				TopNode* topNode = nullptr;
				auto it = m_symbolVarnodes.find(symbolVarnode);
				if (it != m_symbolVarnodes.end()) {
					topNode = it->second;
				}

				m_symbolVarnodes[symbolVarnode] = new TopNode(newExpr);

				// if {newExpr} == {topNode->getNode()}
				if(topNode)
					delete topNode;
			}
		}

		void join(ExecContext* ctx) {
			if (!m_registerExecCtx.m_isFilled) {
				m_registerExecCtx.copyFrom(&ctx->m_registerExecCtx);
			}
			else {
				m_registerExecCtx.join(&ctx->m_registerExecCtx);
			}
		}
	};
};