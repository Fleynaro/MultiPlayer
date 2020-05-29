#pragma once
#include "MovementInstructionInterpreter.h"
#include "ArithmeticInstructionInterpreter.h"
#include "LogicInstructionInterpreter.h"
#include "CondJmpInstructionInterpreter.h"

namespace CE::Decompiler
{
	class InstructionInterpreterDispatcher
	{
	public:
		void execute(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction& instruction) {
			{
				MovementInstructionInterpreter interpreter(block, ctx, &instruction);
				interpreter.execute();
			}

			{
				ArithmeticInstructionInterpreter interpreter(block, ctx, &instruction);
				interpreter.execute();
			}

			{
				LogicInstructionInterpreter interpreter(block, ctx, &instruction);
				interpreter.execute();
			}

			{
				CondJmpInstructionInterpreter interpreter(block, ctx, &instruction);
				interpreter.execute();
			}
		}
	};
};
