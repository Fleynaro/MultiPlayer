#pragma once
#include "DecPCode.h"

namespace CE::Decompiler::PCode
{
	class InstructionPool
	{
		std::list<RegisterVarnode> m_registerVarnodes;
		std::list<ConstantVarnode> m_constantVarnodes;
		std::list<SymbolVarnode> m_symbolVarnodes;
		std::map<int64_t, Instruction::OriginalInstruction> m_origInstructions;
	public:
		InstructionPool()
		{}

		RegisterVarnode* createRegisterVarnode(Register reg) {
			m_registerVarnodes.push_back(RegisterVarnode(reg));
			return &*m_registerVarnodes.rbegin();
		}

		ConstantVarnode* createConstantVarnode(uint64_t value, int size) {
			m_constantVarnodes.push_back(ConstantVarnode(value, size));
			return &*m_constantVarnodes.rbegin();
		}

		SymbolVarnode* createSymbolVarnode(int size) {
			m_symbolVarnodes.push_back(SymbolVarnode(size));
			return &*m_symbolVarnodes.rbegin();
		}

		Instruction::OriginalInstruction* createOrigInstruction(int64_t offset, int length) {
			m_origInstructions[offset] = Instruction::OriginalInstruction(offset, length);
			return &m_origInstructions[offset];
		}

		Instruction* createInstruction(InstructionId id, Varnode* input0, Varnode* input1, Varnode* output, Instruction::OriginalInstruction* origInstr, int orderId = 0) {
			origInstr->m_pcodeInstructions[orderId] = Instruction(id, input0, input1, output, origInstr, orderId);
			return &origInstr->m_pcodeInstructions[orderId];
		}
	};
};