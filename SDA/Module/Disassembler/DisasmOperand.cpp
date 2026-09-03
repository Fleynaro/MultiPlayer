#include "DisasmOperand.h"

using namespace CE;
using namespace CE::Disassembler::Code;

uint64_t Operand::getOffset() {
	return m_offset;
}

ZydisRegister Operand::getRegister() {
	return m_register;
}

void* Operand::getLocationAddress() {
	return (void*)m_offset;
}

bool Operand::isCalculatedAddress() {
	return getType() == AbsAddress || (getType() == Pointer && getRegister() == ZYDIS_REGISTER_NONE);
}

Operand::Type Operand::getType() {
	return m_type;
}

Operand::Operand(uint64_t value, bool isAddr)
	: m_offset(value)
{
	if (isAddr)
		m_type = AbsAddress;
	else m_type = Constant;
}

Operand::Operand(uint64_t base, int offset)
	: m_offset(base + offset)
{
	m_type = Pointer;
}

Operand::Operand(ZydisRegister reg_base, uint64_t offset)
	: m_register(reg_base), m_offset(offset)
{
	m_type = Pointer;
}

Operand::Operand(ZydisRegister reg)
	: m_register(reg)
{
	m_type = Register;
}
