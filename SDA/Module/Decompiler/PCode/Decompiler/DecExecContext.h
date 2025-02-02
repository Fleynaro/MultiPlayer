#pragma once
#include <Decompiler/Graph/DecCodeGraph.h>

namespace CE::Decompiler
{
	class PrimaryDecompiler;
	class ExecContext;

	struct RegisterExecContext
	{
		struct RegisterInfo {
			PCode::Register m_register;
			TopNode* m_expr;
			ExecContext* m_srcExecContext;

			enum REGISTER_USING {
				REGISTER_NOT_USING,
				REGISTER_PARTIALLY_USING,
				REGISTER_FULLY_USING
			} m_using = REGISTER_NOT_USING;
		};

		struct RegisterPart {
			BitMask64 m_regMask; // register range value mask
			BitMask64 m_maskToChange; // that part of m_regMask where m_expr located
			ExprTree::INode* m_expr = nullptr;
		};

		PrimaryDecompiler* m_decompiler;
		std::map<PCode::RegisterId, std::list<RegisterInfo>> m_registers;
		ExecContext* m_execContext;
		bool m_isFilled = false;

		RegisterExecContext(PrimaryDecompiler* decompiler, ExecContext* execContext)
			: m_decompiler(decompiler), m_execContext(execContext)
		{}

		void clear() {
			for (auto& pair : m_registers) {
				auto& registers = pair.second;
				for (auto& regInfo : registers)
					delete regInfo.m_expr;
			}
		}

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
						registers.erase(it2);
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

		static std::list<BitMask64> FindNonIntersectedMasks(const std::list<RegisterInfo>& regs) {
			std::list<BitMask64> masks;
			for (const auto& reg : regs) {
				masks.push_back(reg.m_register.m_valueRangeMask);
			}
			for (auto it1 = masks.begin(); it1 != masks.end(); it1 ++) {
				for (auto it2 = std::next(it1); it2 != masks.end(); it2++) {
					if (!(*it1 & *it2).isZero()) {
						*it1 = *it1 | *it2;
						masks.erase(it2);
					}
				}
			}
			return masks;
		}

		static std::set<BitMask64> CalculateMasks(const std::list<RegisterInfo>& regs1, const std::list<RegisterInfo>& regs2) {
			auto masks1 = FindNonIntersectedMasks(regs1);
			auto masks2 = FindNonIntersectedMasks(regs2);
			std::set<BitMask64> resultMasks;
			for (auto mask1 : masks1) {
				for (auto mask2 : masks2) {
					if(!(mask1 & mask2).isZero())
						resultMasks.insert(mask1 & mask2);
				}
			}
			return resultMasks;
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
					regExpr = new ExprTree::OperationalNode(regExpr, new ExprTree::NumberLeaf(mask.getValue(), regExpr->getSize()), ExprTree::And);
				}

				if (bitShift != 0) {
					regExpr = new ExprTree::OperationalNode(regExpr, new ExprTree::NumberLeaf((uint64_t)abs(bitShift), regExpr->getSize()), bitShift > 0 ? ExprTree::Shr : ExprTree::Shl);
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
		RegisterExecContext m_startRegisterExecCtx; // state before decompiling
		RegisterExecContext m_registerExecCtx; // state during decompiling and after
		PCodeBlock* m_pcodeBlock; // need as a key only

		ExecContext(PrimaryDecompiler* decompiler, PCodeBlock* pcodeBlock = nullptr)
			: m_startRegisterExecCtx(decompiler, this), m_registerExecCtx(m_startRegisterExecCtx), m_pcodeBlock(pcodeBlock)
		{}

		~ExecContext() {
			m_startRegisterExecCtx.clear();
			m_registerExecCtx.clear();

			for (auto& pair : m_symbolVarnodes) {
				auto topNode = pair.second;
				delete topNode;
			}
		}

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
				return new ExprTree::NumberLeaf(varnodeConstant->m_value, varnodeConstant->getMask().getSize());
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