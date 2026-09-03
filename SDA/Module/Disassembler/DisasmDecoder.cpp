#include "DisasmDecoder.h"

using namespace CE;
using namespace CE::Disassembler;
using namespace CE::Disassembler::Code;

Decoder::Decoder(void* startAddr, int size)
	: m_startAddr(startAddr), m_size(size)
{}

void Decoder::decode(const std::function<bool(Instruction*)>& callback)
{
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	ZyanUSize size = getSize();
	m_runtime_address = (ZyanU64)m_startAddr;
	ZydisDecodedInstruction instruction;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)m_runtime_address, size,
		&instruction)))
	{
		m_instr_length = instruction.length;

		doCallback(instruction, callback);

		size -= instruction.length;
		m_runtime_address += instruction.length;
	}
}

int Decoder::getSize() {
	return m_size;
}

ZyanU64 Decoder::getCurrentAddress() {
	return m_runtime_address;
}

ZyanU8 Decoder::getCurrentLength() {
	return m_instr_length;
}

void Decoder::doCallback(const ZydisDecodedInstruction& instruction, const std::function<bool(Instruction*)>& callback)
{
	switch (instruction.mnemonic)
	{
	case ZYDIS_MNEMONIC_CALL: {
		Instructions::Call instr(getOperand(0, instruction));
		callback(&instr);
		return;
	}
	case ZYDIS_MNEMONIC_JMP: {
		Instructions::Jmp instr(getOperand(0, instruction));
		callback(&instr);
		return;
	}

	case ZYDIS_MNEMONIC_MOV: {
		Instructions::Mov instr(getOperand(0, instruction), getOperand(1, instruction));
		callback(&instr);
		return;
	}
	case ZYDIS_MNEMONIC_ADD: {
		Instructions::Add instr(getOperand(0, instruction), getOperand(1, instruction));
		callback(&instr);
		return;
	}
	case ZYDIS_MNEMONIC_SUB: {
		Instructions::Sub instr(getOperand(0, instruction), getOperand(1, instruction));
		callback(&instr);
		return;
	}
	}

	if (instruction.operand_count == 0) {
		Instructions::Generic instr(instruction.mnemonic);
		callback(&instr);
	}
	else if (instruction.operand_count <= 2) {
		Instructions::GenericWithOperands instr(instruction.mnemonic, instruction.operand_count);
		for (int i = 0; i < instruction.operand_count; i++) {
			instr.setOperand(i, getOperand(i, instruction));
		}
		callback(&instr);
	}
}

Operand Decoder::getOperand(int idx, const ZydisDecodedInstruction& instruction)
{
	auto& operand = instruction.operands[idx];

	if (operand.reg.value != ZYDIS_REGISTER_NONE) {
		return Operand(operand.reg.value);
	}
	else if (operand.mem.base != ZYDIS_REGISTER_NONE) {
		if (operand.mem.base == ZYDIS_REGISTER_RIP) {
			return Operand(getCurrentAddress() + getCurrentLength(), (int)operand.mem.disp.value);
		}
		return Operand(operand.mem.base, operand.mem.disp.value);
	}
	else {
		if (operand.imm.is_relative) {
			return Operand(getCurrentAddress() + getCurrentLength() + operand.imm.value.u, true);
		}
	}

	return Operand(0);
}
