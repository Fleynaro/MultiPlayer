#pragma once
#include "AbstarctInstructionInterpreter.h"

namespace CE::Decompiler
{
	class LogicInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		LogicInstructionInterpreter(PrimaryTree::Block* block, ExecutionBlockContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			switch (m_instruction->mnemonic)
			{
			case ZYDIS_MNEMONIC_AND:
				binOperation(ExprTree::And);
				break;
			case ZYDIS_MNEMONIC_OR:
				binOperation(ExprTree::Or);
				break;
			case ZYDIS_MNEMONIC_XOR:
				binOperation(ExprTree::Xor);
				break;
			case ZYDIS_MNEMONIC_SHR: //http://www.club155.ru/x86cmd/SHR
			case ZYDIS_MNEMONIC_SAR:
				binOperation(ExprTree::Shr);
				break;
			case ZYDIS_MNEMONIC_SHL:
				binOperation(ExprTree::Shl);
				break;
			case ZYDIS_MNEMONIC_NOT:
				unaryOperation(ExprTree::Xor, new ExprTree::NumberLeaf(-1));
				break;

			case ZYDIS_MNEMONIC_TEST: {
				Operand op1(m_ctx, &m_instruction->operands[0]);
				Operand op2(m_ctx, &m_instruction->operands[1]);
				auto dstExpr = op1.getExpr();
				auto srcExpr = op2.getExpr();
				auto expr = new ExprTree::OperationalNode(dstExpr, srcExpr, ExprTree::And);
				setFlags(expr, GetMaskBySize(m_instruction->operands[0].size));

				if (m_instruction->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					if (m_instruction->operands[0].reg.value == m_instruction->operands[1].reg.value) {
						m_ctx->setLastCond(dstExpr, new ExprTree::NumberLeaf(0), RegisterFlags::TEST);
					}
				}
				break;
			}

			case ZYDIS_MNEMONIC_BT:
			case ZYDIS_MNEMONIC_BTR: {
				Operand op1(m_ctx, &m_instruction->operands[0]);
				Operand op2(m_ctx, &m_instruction->operands[1]);
				auto expr = new ExprTree::OperationalNode(op2.getExpr(), new ExprTree::NumberLeaf(31), ExprTree::And);
				expr = new ExprTree::OperationalNode(op1.getExpr(), expr, ExprTree::Shr);
				expr = new ExprTree::OperationalNode(expr, new ExprTree::NumberLeaf(1), ExprTree::And);
				auto cond = new ExprTree::Condition(expr, new ExprTree::NumberLeaf(0), ExprTree::Condition::Ne);
				m_ctx->m_flags[ZYDIS_CPUFLAG_CF] = cond;
				m_ctx->clearLastCond(); //???
				break;
			}
			}
		}
	};
};
