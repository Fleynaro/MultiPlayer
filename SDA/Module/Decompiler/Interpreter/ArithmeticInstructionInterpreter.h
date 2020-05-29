#pragma once
#include "AbstarctInstructionInterpreter.h"

namespace CE::Decompiler
{
	class ArithmeticInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		ArithmeticInstructionInterpreter(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			switch (m_instruction->mnemonic)
			{
			case ZYDIS_MNEMONIC_ADD:
				binOperation(ExprTree::Add);
				break;
			case ZYDIS_MNEMONIC_SUB:
				binOperation(ExprTree::Sub);
				break;
			case ZYDIS_MNEMONIC_MUL:
			case ZYDIS_MNEMONIC_IMUL:
			case ZYDIS_MNEMONIC_DIV:
			case ZYDIS_MNEMONIC_IDIV:
			{
				auto opType = ExprTree::Mul;
				bool isSigned = false;
				if (m_instruction->mnemonic == ZYDIS_MNEMONIC_DIV || m_instruction->mnemonic == ZYDIS_MNEMONIC_IDIV) {
					opType = ExprTree::Div;
				}
				if (m_instruction->mnemonic == ZYDIS_MNEMONIC_IMUL || m_instruction->mnemonic == ZYDIS_MNEMONIC_IDIV) {
					isSigned = true;
				}

				auto operandsCount = getFirstExplicitOperandsCount();
				if (operandsCount == 1)
				{
					ZydisRegister reg;
					switch (m_instruction->operands[0].size)
					{
					case 1:
						reg = ZYDIS_REGISTER_AL;
						break;
					case 2:
						reg = ZYDIS_REGISTER_AX;
						break;
					case 4:
						reg = ZYDIS_REGISTER_EAX;
						break;
					default:
						reg = ZYDIS_REGISTER_RAX;
					}

					Operand op(m_ctx, &m_instruction->operands[0]);
					auto srcExpr = new ExprTree::OperationalNode(Register::GetOrCreateExprRegLeaf(m_ctx, reg), op.getExpr(), opType);
					srcExpr->setSigned(isSigned);
					setExprToRegisterDst(reg, srcExpr);
				}
				else if (operandsCount == 2)
				{
					binOperation(opType, isSigned);
				}
				else if (operandsCount == 3)
				{
					tripleOperation(opType, isSigned);
				}
				break;
			}
			/*case ZYDIS_MNEMONIC_MOD:
				binOperation(ExprTree::Mod);
				break;*/
			case ZYDIS_MNEMONIC_INC:
				unaryOperation(ExprTree::Add, new ExprTree::NumberLeaf(1));
				break;
			case ZYDIS_MNEMONIC_DEC:
				unaryOperation(ExprTree::Sub, new ExprTree::NumberLeaf(1));
				break;
			case ZYDIS_MNEMONIC_NEG:
				unaryOperation(ExprTree::Mul, new ExprTree::NumberLeaf(-1));
				break;


			case ZYDIS_MNEMONIC_CMP: {
				Operand op1(m_ctx, &m_instruction->operands[0]);
				Operand op2(m_ctx, &m_instruction->operands[1]);
				auto dstExpr = op1.getExpr();
				auto srcExpr = op2.getExpr();
				auto expr = new ExprTree::OperationalNode(dstExpr, srcExpr, ExprTree::Sub);
				setFlags(expr, GetMaskBySize(m_instruction->operands[0].size));
				m_ctx->setLastCond(dstExpr, srcExpr, RegisterFlags::CMP);
				break;
			}
			}
		}
	};
};