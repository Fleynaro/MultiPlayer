#pragma once
#include <Decompiler/DecStorage.h>
#include "DecExecContext.h"

namespace CE::Decompiler
{
	class PrimaryDecompiler;
};

namespace CE::Decompiler::PCode
{
	class InstructionInterpreter
	{
	public:
		InstructionInterpreter(PrimaryDecompiler* decompiler, PrimaryTree::Block* block, ExecContext* ctx)
			: m_decompiler(decompiler), m_block(block), m_ctx(ctx)
		{}

		void execute(Instruction* instr);

		// create a parameter for some function call using the defined storage (rcx, rdx, [rsp - 0x8], ...)
		ExprTree::INode* buildParameterInfoExpr(ParameterInfo& paramInfo);

		// get expr. value from varnode (register/symbol/constant)
		ExprTree::INode* requestVarnode(PCode::Varnode* varnode);

		// make expression return boolean value: x -> x != 0
		ExprTree::AbstractCondition* toBoolean(ExprTree::INode* node);

		// create assignment line: memVar1 = read([memory location])
		ExprTree::SymbolLeaf* createMemSymbol(ExprTree::ReadValueNode* readValueNode, PCode::Instruction* instr = nullptr);
	private:
		PrimaryDecompiler* m_decompiler;
		PrimaryTree::Block* m_block;
		ExecContext* m_ctx;
		Instruction* m_instr;
	};
};
