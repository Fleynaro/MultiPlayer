#pragma once
#include "PCodeExecutionContext.h"
#include "../../DecStorage.h"

namespace CE::Decompiler::PCode
{
	class InstructionInterpreter
	{
	public:
		void execute(PrimaryTree::Block* block, ExecutionBlockContext* ctx, Instruction* instr);

		ExprTree::INode* buildParameterInfoExpr(ParameterInfo& paramInfo);

		ExprTree::INode* requestVarnode(PCode::Varnode* varnode);

		ExprTree::AbstractCondition* toBoolean(ExprTree::INode* node);

		ExprTree::SymbolLeaf* createMemSymbol(ExprTree::ReadValueNode* readValueNode, PCode::Instruction* instr = nullptr);
	private:
		PrimaryTree::Block* m_block;
		ExecutionBlockContext* m_ctx;
		Instruction* m_instr;
	};
};
