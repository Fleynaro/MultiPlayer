#pragma once
#include "PCodeExecutionContext.h"
#include "../../DecStorage.h"

namespace CE::Decompiler::PCode
{
	class InstructionInterpreter
	{
	public:
		void execute(PrimaryTree::Block* block, ExecutionBlockContext* ctx, Instruction* instr);

		// create a parameter for some function call using the defined storage (rcx, rdx, [rsp - 0x8], ...)
		ExprTree::INode* buildParameterInfoExpr(ParameterInfo& paramInfo);

		// get expr. value from varnode (register/symbol/constant)
		ExprTree::INode* requestVarnode(PCode::Varnode* varnode);

		// make expression return boolean value: x -> x != 0
		ExprTree::AbstractCondition* toBoolean(ExprTree::INode* node);

		// create assignment line: memVar1 = read([memory location])
		ExprTree::SymbolLeaf* createMemSymbol(ExprTree::ReadValueNode* readValueNode, PCode::Instruction* instr = nullptr);
	private:
		PrimaryTree::Block* m_block;
		ExecutionBlockContext* m_ctx;
		Instruction* m_instr;
	};
};
