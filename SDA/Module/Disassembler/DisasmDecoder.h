#pragma once
#include "DisasmInstructions.h"

namespace CE::Disassembler
{
	class Decoder
	{
	public:
		Decoder(void* startAddr, int size);

		void decode(const std::function<bool(Code::Instruction*)>& callback);

		int getSize();

		ZyanU64 getCurrentAddress();

		ZyanU8 getCurrentLength();
	private:
		void* m_startAddr;
		int m_size;
		ZyanU64 m_runtime_address;
		ZyanU8 m_instr_length;

		void doCallback(const ZydisDecodedInstruction& instruction, const std::function<bool(Code::Instruction*)>& callback);

		Code::Operand getOperand(int idx, const ZydisDecodedInstruction& instruction);
	};
};