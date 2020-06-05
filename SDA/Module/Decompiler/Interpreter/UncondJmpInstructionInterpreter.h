#pragma once
#include "AbstarctInstructionInterpreter.h"

namespace CE::Decompiler
{
	class UncondJmpInstructionInterpreter : public AbstractInstructionInterpreter
	{
	public:
		UncondJmpInstructionInterpreter(PrimaryTree::Block* block, ExecutionBlockContext* ctx, const ZydisDecodedInstruction* instruction);

		void execute() override;
	};
};