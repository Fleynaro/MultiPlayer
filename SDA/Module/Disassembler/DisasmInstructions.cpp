#include "DisasmInstructions.h"

using namespace CE;
using namespace CE::Disassembler::Code;
using namespace CE::Disassembler::Code::Instructions;

bool Instruction::isGeneric() {
	return false;
}

bool Instruction::isJumping() {
	return false;
}

bool Instruction::isBasicManipulating() {
	return false;
}



JumpInstruction::JumpInstruction(Operand location)
{
	setOperand(0, location);
}

bool JumpInstruction::isJumping() {
	return true;
}

bool JumpInstruction::hasAbsoluteAddr() {
	return getOperand(0).isCalculatedAddress();
}

void* JumpInstruction::getAbsoluteAddr() {
	return getOperand(0).getLocationAddress();
}



Call::Call(Operand location)
	: JumpInstruction(location)
{}

ZydisMnemonic_ Call::getMnemonicId() {
	return ZYDIS_MNEMONIC_CALL;
}



Jmp::Jmp(Operand location)
	: JumpInstruction(location)
{}

ZydisMnemonic_ Jmp::getMnemonicId() {
	return ZYDIS_MNEMONIC_JMP;
}



BasicManipulation::BasicManipulation(Operand op1, Operand op2)
{
	setOperand(0, op1);
	setOperand(1, op2);
}

bool BasicManipulation::isBasicManipulating() {
	return true;
}



Mov::Mov(Operand op1, Operand op2)
	: BasicManipulation(op1, op2)
{}

ZydisMnemonic_ Mov::getMnemonicId() {
	return ZYDIS_MNEMONIC_MOV;
}



Add::Add(Operand op1, Operand op2)
	: BasicManipulation(op1, op2)
{}

ZydisMnemonic_ Add::getMnemonicId() {
	return ZYDIS_MNEMONIC_ADD;
}



Sub::Sub(Operand op1, Operand op2)
	: BasicManipulation(op1, op2)
{}

ZydisMnemonic_ Sub::getMnemonicId() {
	return ZYDIS_MNEMONIC_SUB;
}



Generic::Generic(ZydisMnemonic_ mnemonicId)
	: m_mnemonicId(mnemonicId)
{}

ZydisMnemonic_ Generic::getMnemonicId() {
	return m_mnemonicId;
}

bool Generic::isGeneric() {
	return true;
}

void* Generic::getAbsoluteAddr() {
	return nullptr;
}

int Generic::getOperandCount() {
	return 0;
}



GenericWithOperands::GenericWithOperands(ZydisMnemonic_ mnemonicId, int operandCount)
	: Generic(mnemonicId), m_operandCount(operandCount)
{}

void* GenericWithOperands::getAbsoluteAddr() {
	for (int i = 0; i < m_operandCount; i++) {
		if (getOperand(i).isCalculatedAddress()) {
			return getOperand(i).getLocationAddress();
		}
	}
	return nullptr;
}

int GenericWithOperands::getOperandCount() {
	return m_operandCount;
}
