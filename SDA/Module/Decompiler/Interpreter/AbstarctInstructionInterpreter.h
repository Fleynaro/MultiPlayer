#pragma once
#include "../DecOperand.h"
#include "../ExprTree/ExprTreeFuncCallContext.h"

namespace CE::Decompiler
{
	class AbstractInstructionInterpreter
	{
	public:
		AbstractInstructionInterpreter(PrimaryTree::Block* block, ExecutionBlockContext* ctx, const ZydisDecodedInstruction* instruction)
			: m_block(block), m_ctx(ctx), m_instruction(instruction)
		{}

		virtual void execute() = 0;

	protected:
		PrimaryTree::Block* m_block;
		ExecutionBlockContext* m_ctx;
		const ZydisDecodedInstruction* m_instruction;

		void unaryOperation(ExprTree::OperationType opType, ExprTree::Node* srcExpr, ExprTree::Node* dstExpr = nullptr, bool isSettingFlags = true) {
			Operand op(m_ctx, &m_instruction->operands[0]);
			if (!op.isDst())
				return;

			if (!dstExpr) {
				dstExpr = op.getExpr();
			}
			assignment(m_instruction->operands[0], new ExprTree::OperationalNode(dstExpr, srcExpr, opType), dstExpr, isSettingFlags);
		}

		void binOperation(ExprTree::OperationType opType, bool isSigned = false, bool isSettingFlags = true) {
			Operand op1(m_ctx, &m_instruction->operands[0]);
			Operand op2(m_ctx, &m_instruction->operands[1]);
			if (!op1.isDst() || !op2.isValid())
				return;

			ExprTree::Node* dstExpr = nullptr;
			ExprTree::Node* srcExpr = op2.getExpr();

			if (isSigned) {
				srcExpr = new ExprTree::CastNode(srcExpr, op1.getSize(), true);
			}

			if (opType != ExprTree::None) {
				dstExpr = op1.getExpr();
				if (isSigned) {
					dstExpr = new ExprTree::CastNode(dstExpr, op1.getSize(), true);
				}
				srcExpr = new ExprTree::OperationalNode(dstExpr, srcExpr, opType);
			}

			assignment(m_instruction->operands[0], srcExpr, dstExpr, isSettingFlags);
		}

		void tripleOperation(ExprTree::OperationType opType, bool isSigned = false, bool isSettingFlags = true) {
			Operand op1(m_ctx, &m_instruction->operands[0]);
			Operand op2(m_ctx, &m_instruction->operands[1]);
			Operand op3(m_ctx, &m_instruction->operands[2]);
			if (!op1.isDst() || !op2.isValid() || !op2.isValid())
				return;

			auto expr1 = op2.getExpr();
			auto expr2 = op3.getExpr();
			if (isSigned) {
				expr1 = new ExprTree::CastNode(expr1, op1.getSize(), true);
				expr2 = new ExprTree::CastNode(expr2, op1.getSize(), true);
			}

			auto srcExpr = new ExprTree::OperationalNode(expr1, expr2, opType);
			assignment(m_instruction->operands[0], srcExpr, nullptr, isSettingFlags);
		}

		void assignment(const ZydisDecodedOperand& dstOperand, ExprTree::Node* srcExpr, ExprTree::Node* dstExpr, bool isSettingFlags) {
			if (dstOperand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
				if (!dstExpr) {
					Operand op(m_ctx, &dstOperand);
					dstExpr = op.getExpr();
				}
				if (isSettingFlags)
					setFlags(srcExpr, GetMaskBySize(dstOperand.size));
				m_block->addSeqLine(dstExpr, srcExpr);
			}
			else {
				setExprToRegisterDst(dstOperand.reg.value, srcExpr, isSettingFlags);
			}
		}

		void setExprToRegisterDst(const Register& dstReg, ExprTree::Node* srcExpr, bool isSettingFlags = true) {
			m_ctx->setRegister(dstReg, srcExpr);
			if (isSettingFlags)
				setFlags(srcExpr, dstReg.m_mask);

			for (auto sameReg : dstReg.m_sameRegisters) {
				if (sameReg.first == dstReg.m_reg)
					continue;
				auto it = m_ctx->m_registers.find(sameReg.first);
				if (it != m_ctx->m_registers.end()) {
					//exception: eax(no ax, ah, al!) overwrite rax!!!
					if (GetMaskWithException(dstReg.m_mask) >= GetMaskWithException(sameReg.second)) {
						m_ctx->m_registers.erase(it);
						delete it->second;
					}
				}
			}
		}

		void setFlags(ExprTree::Node* expr, uint64_t mask = -1) {
			auto maskedExpr = expr;
			if (mask != -1) {
				maskedExpr = new ExprTree::OperationalNode(expr, new ExprTree::NumberLeaf(mask), ExprTree::And);
			}
			m_ctx->setFlag(ZYDIS_CPUFLAG_ZF, new ExprTree::Condition(maskedExpr, new ExprTree::NumberLeaf(0), ExprTree::Condition::Eq));
			m_ctx->setFlag(ZYDIS_CPUFLAG_SF, new ExprTree::Condition(maskedExpr, new ExprTree::NumberLeaf(0), ExprTree::Condition::Lt));

			auto bitsAmountExpr = new ExprTree::OperationalNode(expr, new ExprTree::NumberLeaf(0x8), ExprTree::GetBits);
			auto evenOfBitsAmountExpr = new ExprTree::OperationalNode(bitsAmountExpr, new ExprTree::NumberLeaf(2), ExprTree::Mod);
			m_ctx->setFlag(ZYDIS_CPUFLAG_PF, new ExprTree::Condition(evenOfBitsAmountExpr, new ExprTree::NumberLeaf(0), ExprTree::Condition::Eq));
			//flags CF and OF...
			m_ctx->clearLastCond();
		}

		int getFirstExplicitOperandsCount() {
			int result = 0;
			while (result < m_instruction->operand_count) {
				if (m_instruction->operands[result].visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
					break;
				result++;
			}
			return result;
		}
	};
};