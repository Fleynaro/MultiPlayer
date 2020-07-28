#pragma once
#include "DecExecutionContext.h"

namespace CE::Decompiler::PCode
{
	class InstructionInterpreter
	{
	public:
		void execute(PrimaryTree::Block* block, ExecutionBlockContext* ctx, Instruction* instr);

		ExprTree::Node* requestVarnode(PCode::Varnode* varnode);

		ExprTree::ICondition* toBoolean(ExprTree::Node* node);
	private:
		PrimaryTree::Block* m_block;
		ExecutionBlockContext* m_ctx;
		Instruction* m_instr;
	};
};
