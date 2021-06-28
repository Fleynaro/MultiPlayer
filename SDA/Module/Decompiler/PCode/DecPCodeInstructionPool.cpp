#include "DecPCodeInstructionPool.h"

using namespace CE;
using namespace CE::Decompiler;
using namespace CE::Decompiler::PCode;

RegisterVarnode* InstructionPool::createRegisterVarnode(Register reg) {
	m_registerVarnodes.push_back(RegisterVarnode(reg));
	return &*m_registerVarnodes.rbegin();
}

ConstantVarnode* InstructionPool::createConstantVarnode(uint64_t value, int size) {
	m_constantVarnodes.push_back(ConstantVarnode(value, size));
	return &*m_constantVarnodes.rbegin();
}

Instruction* InstructionPool::getInstructionAt(int64_t instrOffset) {
	auto byteOffset = instrOffset >> 8;
	auto instrOrder = instrOffset & 0xFF;
	auto it = m_origInstructions.find(byteOffset);
	if (it == m_origInstructions.end())
		throw InstructionNotFoundException();
	auto origInstr = &it->second;
	auto it2 = origInstr->m_pcodeInstructions.find(instrOrder);
	if (it2 == origInstr->m_pcodeInstructions.end())
		throw InstructionNotFoundException();
	return &it2->second;
}

void InstructionPool::modifyInstruction(Instruction* instr, MODIFICATOR mod) {
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

SymbolVarnode* InstructionPool::createSymbolVarnode(int size) {
	m_symbolVarnodes.push_back(SymbolVarnode(size));
	return &*m_symbolVarnodes.rbegin();
}