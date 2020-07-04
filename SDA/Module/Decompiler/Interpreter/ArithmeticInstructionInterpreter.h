#pragma once
#include "AbstarctInstructionInterpreter.h"

namespace CE::Decompiler
{
	class ArithmeticInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		ArithmeticInstructionInterpreter(PrimaryTree::Block* block, ExecutionBlockContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			auto size = m_instruction->operands[0].size / 8;
			auto mask = GetMaskBySize(size);

			switch (m_instruction->mnemonic)
			{
			case ZYDIS_MNEMONIC_ADD:
				binOperation(ExprTree::Add);
				break;
			case ZYDIS_MNEMONIC_SUB:
			case ZYDIS_MNEMONIC_CMP: {
				Operand op1(m_ctx, &m_instruction->operands[0]);
				Operand op2(m_ctx, &m_instruction->operands[1]);

				auto dstExpr = op1.getExpr();
				auto srcExpr = op2.getExpr();
				srcExpr = new ExprTree::OperationalNode(srcExpr, new ExprTree::NumberLeaf(-1 & mask), ExprTree::Mul); //negative
				auto expr = new ExprTree::OperationalNode(dstExpr, srcExpr, ExprTree::Add);
				setFlags(expr, mask);
				m_ctx->setLastCond(dstExpr, srcExpr, RegisterFlags::CMP);

				if (m_instruction->mnemonic == ZYDIS_MNEMONIC_SUB) {
					assignment(m_instruction->operands[0], expr, dstExpr, false);
				}
				break;
			}
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

				ExprTree::Node* expr1 = nullptr;
				ExprTree::Node* expr2 = nullptr;
				auto operandsCount = getFirstExplicitOperandsCount();
				if (operandsCount == 1)
				{
					ZydisRegister reg;
					switch (size)
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
					expr1 = m_ctx->requestRegister(reg);
					expr2 = op.getExpr();
					if (isSigned) {
						expr1 = new ExprTree::CastNode(expr1, size, true);
						expr2 = new ExprTree::CastNode(expr2, size, true);
					}
					auto expr = new ExprTree::OperationalNode(expr1, expr2, opType);
					setExprToRegisterDst(reg, expr);
				}
				else if (operandsCount == 2)
				{
					binOperation(opType, isSigned);
					
					if (opType == ExprTree::Div) {
						Operand op1(m_ctx, &m_instruction->operands[0]);
						Operand op2(m_ctx, &m_instruction->operands[1]);
						expr1 = op1.getExpr();
						expr2 = op2.getExpr();
					}
				}
				else if (operandsCount == 3)
				{
					tripleOperation(opType, isSigned);

					if (opType == ExprTree::Div) {
						Operand op1(m_ctx, &m_instruction->operands[1]);
						Operand op2(m_ctx, &m_instruction->operands[2]);
						expr1 = op1.getExpr();
						expr2 = op2.getExpr();
					}
				}

				if (opType == ExprTree::Div) {
					ZydisRegister reg;
					switch (size)
					{
					case 1:
						reg = ZYDIS_REGISTER_AH;
						break;
					case 2:
						reg = ZYDIS_REGISTER_DX;
						break;
					case 4:
						reg = ZYDIS_REGISTER_EDX;
						break;
					default:
						reg = ZYDIS_REGISTER_RDX;
					}

					if (isSigned) {
						expr1 = new ExprTree::CastNode(expr1, size, true);
						expr2 = new ExprTree::CastNode(expr2, size, true);
					}
					auto expr = new ExprTree::OperationalNode(expr1, expr2, ExprTree::Mod);
					setExprToRegisterDst(reg, expr);
				}
				break;
			}
			/*case ZYDIS_MNEMONIC_MOD:
				binOperation(ExprTree::Mod);
				break;*/
			case ZYDIS_MNEMONIC_INC:
				unaryOperation(ExprTree::Add, new ExprTree::NumberLeaf(1 & mask));
				break;
			case ZYDIS_MNEMONIC_DEC:
				unaryOperation(ExprTree::Add, new ExprTree::NumberLeaf(-1 & mask));
				break;
			case ZYDIS_MNEMONIC_NEG:
				unaryOperation(ExprTree::Mul, new ExprTree::NumberLeaf(-1 & mask));
				break;
			}
		}
	};
};