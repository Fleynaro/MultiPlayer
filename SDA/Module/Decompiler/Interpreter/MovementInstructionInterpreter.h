#pragma once
#include "AbstarctInstructionInterpreter.h"

namespace CE::Decompiler
{
	class MovementInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		MovementInstructionInterpreter(PrimaryTree::Block* block, ExecutionBlockContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			switch (m_instruction->mnemonic)
			{
			case ZYDIS_MNEMONIC_XCHG: {
				Operand op1(m_ctx, &m_instruction->operands[0]);
				Operand op2(m_ctx, &m_instruction->operands[1]);
				auto expr1 = op1.getExpr();
				auto expr2 = op2.getExpr();
				
				auto opNode = new ExprTree::OperationalNode(expr1, expr2, ExprTree::None);
				setExprToRegisterDst(m_instruction->operands[0].reg.value, nullptr, false);
				setExprToRegisterDst(m_instruction->operands[1].reg.value, nullptr, false);
				setExprToRegisterDst(m_instruction->operands[0].reg.value, expr2, false);
				setExprToRegisterDst(m_instruction->operands[1].reg.value, expr1, false);
				opNode->removeBy(nullptr);
				break;
			}

			case ZYDIS_MNEMONIC_MOV:
			case ZYDIS_MNEMONIC_MOVZX:
			case ZYDIS_MNEMONIC_MOVSX:
			case ZYDIS_MNEMONIC_MOVSXD:
			case ZYDIS_MNEMONIC_LEA: {
				bool isSigned = false;
				if (m_instruction->mnemonic == ZYDIS_MNEMONIC_MOVSX || m_instruction->mnemonic == ZYDIS_MNEMONIC_MOVSXD) {
					isSigned = true;
				}
				bool isSettingFlag = false;
				binOperation(ExprTree::None, isSigned, isSettingFlag);
				break;
			}

			//https://www.jaist.ac.jp/iscenter-new/mpc/altix/altixdata/opt/intel/vtune/doc/users_guide/mergedProjects/analyzer_ec/mergedProjects/reference_olh/mergedProjects/instructions/instruct32_hh/vc35.htm
			case ZYDIS_MNEMONIC_CMOVZ:
			case ZYDIS_MNEMONIC_CMOVNZ:
			case ZYDIS_MNEMONIC_CMOVL:
			case ZYDIS_MNEMONIC_CMOVLE:
			case ZYDIS_MNEMONIC_CMOVNL:
			case ZYDIS_MNEMONIC_CMOVNLE:
			{
				auto cond = ExprTree::Condition::None;
				if (m_ctx->m_lastCond.flags != RegisterFlags::None) {
					switch (m_instruction->mnemonic)
					{
					case ZYDIS_MNEMONIC_CMOVZ:
						cond = ExprTree::Condition::Eq;
						break;
					case ZYDIS_MNEMONIC_CMOVNZ:
						cond = ExprTree::Condition::Ne;
						break;
					case ZYDIS_MNEMONIC_CMOVL:
						cond = ExprTree::Condition::Lt;
						break;
					case ZYDIS_MNEMONIC_CMOVLE:
						cond = ExprTree::Condition::Le;
						break;
					case ZYDIS_MNEMONIC_CMOVNL:
						cond = ExprTree::Condition::Gt;
						break;
					case ZYDIS_MNEMONIC_CMOVNLE:
						cond = ExprTree::Condition::Ge;
						break;
					}
				}

				if (cond != ExprTree::Condition::None)
				{
					Operand op1(m_ctx, &m_instruction->operands[0]);
					Operand op2(m_ctx, &m_instruction->operands[1]);
					auto dstExpr = op1.getExpr();
					auto srcExpr = op2.getExpr();
					auto condExpr = new ExprTree::Condition(m_ctx->m_lastCond.leftNode, m_ctx->m_lastCond.rightNode, cond);
					auto ternaryCondExpr = new ExprTree::TernaryOperationalNode(condExpr, srcExpr, dstExpr);
					setExprToRegisterDst(m_instruction->operands[0].reg.value, ternaryCondExpr);
				}
				else {

				}

				break;
			}

			//http://faydoc.tripod.com/cpu/setnz.htm
			case ZYDIS_MNEMONIC_SETZ:
			case ZYDIS_MNEMONIC_SETNZ:
			case ZYDIS_MNEMONIC_SETL:
			case ZYDIS_MNEMONIC_SETLE:
			case ZYDIS_MNEMONIC_SETNL:
			case ZYDIS_MNEMONIC_SETNLE:
			{
				auto cond = ExprTree::Condition::None;
				if (m_ctx->m_lastCond.flags != RegisterFlags::None) {
					switch (m_instruction->mnemonic)
					{
					case ZYDIS_MNEMONIC_SETZ:
						cond = ExprTree::Condition::Eq;
						break;
					case ZYDIS_MNEMONIC_SETNZ:
						cond = ExprTree::Condition::Ne;
						break;
					case ZYDIS_MNEMONIC_SETL:
						cond = ExprTree::Condition::Lt;
						break;
					case ZYDIS_MNEMONIC_SETLE:
						cond = ExprTree::Condition::Le;
						break;
					case ZYDIS_MNEMONIC_SETNL:
						cond = ExprTree::Condition::Gt;
						break;
					case ZYDIS_MNEMONIC_SETNLE:
						cond = ExprTree::Condition::Ge;
						break;
					}
				}

				if (cond != ExprTree::Condition::None)
				{
					assignment(m_instruction->operands[0], new ExprTree::Condition(m_ctx->m_lastCond.leftNode, m_ctx->m_lastCond.rightNode, cond), nullptr, false);
				}
				else {
					if (m_instruction->mnemonic == ZYDIS_MNEMONIC_SETNZ) {
						assignment(m_instruction->operands[0], new ExprTree::CompositeCondition(m_ctx->getFlag(ZYDIS_CPUFLAG_ZF), nullptr, ExprTree::CompositeCondition::Not), nullptr, false);
					}
				}

				break;
			}
			}
		}
	};
};
