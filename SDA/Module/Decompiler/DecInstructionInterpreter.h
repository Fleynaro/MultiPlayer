#pragma once
#include "DecExecutionContext.h"

namespace CE::Decompiler::PCode
{
	class InstructionInterpreter
	{
	public:
		void execute(PrimaryTree::Block* block, ExecutionBlockContext* ctx, Instruction* instr) {
			switch (instr->m_id)
			{
			case InstructionId::COPY:
			{
				break;
			}
			}
		}
	};
};
