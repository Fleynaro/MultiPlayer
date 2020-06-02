#pragma once
#include "MovementInstructionInterpreter.h"
#include "StackInstructionInterpreter.h"
#include "ArithmeticInstructionInterpreter.h"
#include "LogicInstructionInterpreter.h"
#include "CondJmpInstructionInterpreter.h"
#include "UncondJmpInstructionInterpreter.h"

namespace CE::Decompiler
{
	class InstructionInterpreterDispatcher
	{
	public:
		void execute(PrimaryTree::Block* block, ExecutionContext* ctx, const ZydisDecodedInstruction& instruction) {
			ctx->m_offset += instruction.length;
			
			{
				MovementInstructionInterpreter interpreter(block, ctx, &instruction);
				interpreter.execute();
			}

			{
				StackInstructionInterpreter interpreter(block, ctx, &instruction);
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

			{
				UncondJmpInstructionInterpreter interpreter(block, ctx, &instruction);
				interpreter.execute();
			}
		}
	};
};
