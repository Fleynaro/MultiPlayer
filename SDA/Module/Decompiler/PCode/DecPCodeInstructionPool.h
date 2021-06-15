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
		// exceptions
		class InstructionNotFoundException : public std::exception {};

		// some orig. instruction can be changed during image analysis (JMP -> CALL/RET)
		enum MODIFICATOR {
			MODIFICATOR_JMP_CALL
		};
		std::map<int64_t, MODIFICATOR> m_modifiedInstructions;

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
			auto instr = Instruction(id, input0, input1, output, origInstr, orderId);
			origInstr->m_pcodeInstructions[orderId] = instr;
			// check if can modificate the instruction
			auto it = m_modifiedInstructions.find(instr.getOffset());
			if (it != m_modifiedInstructions.end()) {
				modifyInstruction(&instr, it->second);
			}
			return &origInstr->m_pcodeInstructions[orderId];
		}

		void modifyInstruction(Instruction* instr, MODIFICATOR mod) {
			switch (mod)
			{
			case MODIFICATOR_JMP_CALL:
				// replace JMP with CALL and add RET
				instr->m_id = PCode::InstructionId::CALL;
				createInstruction(PCode::InstructionId::RETURN, nullptr, nullptr, nullptr, instr->m_origInstruction, 1);
				break;
			}
			m_modifiedInstructions[instr->getOffset()] = mod;
		}

		// get pcode instruction at a complex offset (offset + order)
		Instruction* getInstructionAt(int64_t instrOffset) {
			auto byteOffset = instrOffset >> 8;
			auto instrOrder = instrOffset & 0xFF;
			auto it = m_origInstructions.find(byteOffset);
			if (it == m_origInstructions.end())
				throw InstructionNotFoundException();
			auto origInstr = &it->second;
			auto it2 = origInstr->m_pcodeInstructions.find(byteOffset);
			if (it2 == origInstr->m_pcodeInstructions.end())
				throw InstructionNotFoundException();
			return &it2->second;
		}
	};
};