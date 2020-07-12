#pragma once
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>
#include "DecPCode.h"

namespace CE::Decompiler::PCode
{
	class TranslatorX86
	{
	public:
		InstructionMapType m_result;

		TranslatorX86()

		{}

		void start(void* addr, int size) {
			ZydisDecoder decoder;
			ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

			int curOffset = 0;
			ZyanUSize curSize = (ZyanUSize)size;
			auto curAddress = (ZyanU64)addr;
			ZydisDecodedInstruction curInstruction;
			while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)curAddress, curSize,
				&curInstruction)))
			{
				translateInstruction(curOffset, curInstruction);
				curSize -= curInstruction.length;
				curOffset += curInstruction.length;
				curAddress += curInstruction.length;
			}
		}

	private:
		void translateInstruction(int offset, const ZydisDecodedInstruction& instr) {
			m_result.insert(std::make_pair(offset, getTranslatedInstruction(instr)));
		}

		Instruction* getTranslatedInstruction(const ZydisDecodedInstruction& instr) {
			auto trInstr = new Instruction;
			
			switch (instr.mnemonic)
			{
			case ZYDIS_MNEMONIC_MOV:
			case ZYDIS_MNEMONIC_MOVZX:
			case ZYDIS_MNEMONIC_MOVSX:
			case ZYDIS_MNEMONIC_MOVSXD:
			case ZYDIS_MNEMONIC_LEA: {
				trInstr->addMicroInstruction();
				break;
			}
			}

			return trInstr;
		}

		//requestOperand dst/src
		//setToDstOp
	};
};