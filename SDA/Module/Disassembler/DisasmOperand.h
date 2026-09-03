#pragma once

#include "main.h"
#include <inttypes.h>
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

namespace CE::Disassembler::Code
{
	class Operand
	{
	public:
		enum Type {
			Register,
			Constant,
			Pointer,
			AbsAddress
		};

		Operand() = default;

		Operand(ZydisRegister reg);

		Operand(ZydisRegister reg_base, uint64_t offset);

		Operand(uint64_t base, int offset);

		Operand(uint64_t value, bool isAddr = false);

		Type getType();

		bool isCalculatedAddress();

		void* getLocationAddress();

		ZydisRegister getRegister();

		uint64_t getOffset();
	private:
		Type m_type = Constant;
		ZydisRegister m_register = ZYDIS_REGISTER_NONE;
		uint64_t m_offset = 0;
	};
};