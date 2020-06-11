#pragma once
#include "AbstarctInstructionInterpreter.h"

namespace CE::Decompiler
{
	class CondJmpInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		CondJmpInstructionInterpreter(PrimaryTree::Block* block, ExecutionBlockContext* ctx, const ZydisDecodedInstruction* instruction)
			: AbstractInstructionInterpreter(block, ctx, instruction)
		{}

		void execute() override {
			auto cond = ExprTree::Condition::None;
			if (m_ctx->m_lastCond.flags != RegisterFlags::None) {
				switch (m_instruction->mnemonic)
				{
				case ZYDIS_MNEMONIC_JZ:
					cond = ExprTree::Condition::Eq;
					break;
				case ZYDIS_MNEMONIC_JNZ:
					cond = ExprTree::Condition::Ne;
					break;
				case ZYDIS_MNEMONIC_JL:
					cond = ExprTree::Condition::Lt;
					break;
				case ZYDIS_MNEMONIC_JLE:
					cond = ExprTree::Condition::Le;
					break;
				case ZYDIS_MNEMONIC_JNLE:
					cond = ExprTree::Condition::Gt;
					break;
				case ZYDIS_MNEMONIC_JNL:
					cond = ExprTree::Condition::Ge;
					break;
				}
			}

			if (cond != ExprTree::Condition::None)
			{
				auto condition = new ExprTree::Condition(m_ctx->m_lastCond.leftNode, m_ctx->m_lastCond.rightNode, cond);
				condition->inverse();
				m_block->setJumpCondition(condition);
			}
			else {
				//сделать movsnz и тернарный оператор
			}
		}
	};
};