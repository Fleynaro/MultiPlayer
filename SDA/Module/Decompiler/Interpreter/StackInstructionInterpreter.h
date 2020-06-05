#pragma once
#include "AbstarctInstructionInterpreter.h"

namespace CE::Decompiler
{
	class StackInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		StackInstructionInterpreter(PrimaryTree::Block* block, ExecutionBlockContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			switch (m_instruction->mnemonic)
			{
			case ZYDIS_MNEMONIC_PUSH:
			case ZYDIS_MNEMONIC_POP: {
				auto regRsp = Register::GetOrCreateExprRegLeaf(m_ctx, ZYDIS_REGISTER_RSP);
				if (m_instruction->mnemonic == ZYDIS_MNEMONIC_PUSH) {
					auto expr = new ExprTree::OperationalNode(regRsp, new ExprTree::NumberLeaf(0x8), ExprTree::Sub);
					setExprToRegisterDst(ZYDIS_REGISTER_RSP, expr, false);

					auto& operand = m_instruction->operands[0];
					Operand op(m_ctx, &operand);
					auto dstExpr = new ExprTree::OperationalNode(expr, new ExprTree::NumberLeaf(operand.size / 8), ExprTree::readValue);
					auto srcExpr = op.getExpr();
					m_block->addLine(dstExpr, srcExpr);
				}
				else {
					auto& operand = m_instruction->operands[0];
					auto srcExpr = new ExprTree::OperationalNode(regRsp, new ExprTree::NumberLeaf(operand.size / 8), ExprTree::readValue);
					assignment(operand, srcExpr, nullptr, false);

					auto expr = new ExprTree::OperationalNode(regRsp, new ExprTree::NumberLeaf(0x8), ExprTree::Add);
					setExprToRegisterDst(ZYDIS_REGISTER_RSP, expr, false);
				}
				break;
			}

			case ZYDIS_MNEMONIC_RET: {
				m_block->addLine(new ExprTree::NumberLeaf(0x0), m_ctx->getRegister(ZYDIS_REGISTER_RAX));
				//m_block->addLine(new ExprTree::NumberLeaf(0x0), m_ctx->getRegister(ZYDIS_REGISTER_ZMM0));
				break;
			}
			}
		}
	};
};