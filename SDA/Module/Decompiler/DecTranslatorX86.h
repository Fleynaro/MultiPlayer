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
		std::list<Instruction*> m_result;

		TranslatorX86()

		{}

		void start(void* addr, int size) {
			ZydisDecoder decoder;
			ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

			ZyanUSize curSize = (ZyanUSize)size;
			m_curAddr = (ZyanU64)addr;
			ZydisDecodedInstruction curInstruction;
			while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)m_curAddr, curSize,
				&curInstruction)))
			{
				m_curInstr = &curInstruction;
				translateCurInstruction();
				curSize -= curInstruction.length;
				m_curOffset += curInstruction.length;
				m_curAddr += curInstruction.length;
				m_curOrderId = 0;
			}
		}

	private:
		ZydisDecodedInstruction* m_curInstr;
		ZyanU64 m_curAddr = 0x0;
		int m_curOffset = 0x0;
		int m_curOrderId = 0;

		enum class FlagCond {
			NONE,
			Z,
			NZ,
			L,
			LE,
			NL,
			NLE
		};

		void translateCurInstruction() {
			auto mnemonic = m_curInstr->mnemonic;
			auto size = m_curInstr->operands[0].size / 8;
			auto operandsCount = getFirstExplicitOperandsCount();
			
			switch (mnemonic)
			{
			case ZYDIS_MNEMONIC_XCHG:
			{
				Varnode* varnodeInput0 = requestOperandValue(m_curInstr->operands[0], size);
				Varnode* varnodeInput1 = requestOperandValue(m_curInstr->operands[1], size);
				auto varnodeTemp = new SymbolVarnode(size);
				addMicroInstruction(InstructionId::COPY, varnodeInput0, nullptr, varnodeTemp);
				addMicroInstruction(InstructionId::COPY, varnodeInput0, nullptr, varnodeInput1);
				addMicroInstruction(InstructionId::COPY, varnodeTemp, nullptr, varnodeInput0);
				break;
			}

			case ZYDIS_MNEMONIC_MOV:
			case ZYDIS_MNEMONIC_MOVZX:
			case ZYDIS_MNEMONIC_MOVSX:
			case ZYDIS_MNEMONIC_MOVSXD:
			case ZYDIS_MNEMONIC_LEA:
			{
				auto operand = m_curInstr->operands[1];
				auto varnode = requestOperandValue(operand, size, nullptr, operand.actions != 0);

				auto instrId = InstructionId::COPY;
				switch (mnemonic) {
				case ZYDIS_MNEMONIC_MOVSX:
					instrId = InstructionId::INT_SEXT;
					break;
				case ZYDIS_MNEMONIC_MOVZX:
					instrId = InstructionId::INT_ZEXT;
					break;
				}
				addGenericOperation(instrId, varnode, nullptr);
				break;
			}

			case ZYDIS_MNEMONIC_ADD:
			case ZYDIS_MNEMONIC_INC:
			case ZYDIS_MNEMONIC_DEC:
			case ZYDIS_MNEMONIC_SUB:
			case ZYDIS_MNEMONIC_CMP:
			case ZYDIS_MNEMONIC_NEG:
			case ZYDIS_MNEMONIC_MUL:
			case ZYDIS_MNEMONIC_IMUL:
			case ZYDIS_MNEMONIC_DIV:
			case ZYDIS_MNEMONIC_IDIV:
			case ZYDIS_MNEMONIC_AND:
			case ZYDIS_MNEMONIC_TEST:
			case ZYDIS_MNEMONIC_OR:
			case ZYDIS_MNEMONIC_XOR:
			case ZYDIS_MNEMONIC_SHL:
			case ZYDIS_MNEMONIC_SHR:
			case ZYDIS_MNEMONIC_SAR:
			case ZYDIS_MNEMONIC_BT:
			case ZYDIS_MNEMONIC_BTR:
			{
				Varnode* memLocVarnode = nullptr;
				Varnode* varnodeInput0 = requestOperandValue(m_curInstr->operands[0], size, &memLocVarnode);
				Varnode* varnodeInput1 = nullptr;
				Varnode* varnodeInput2 = nullptr;
				Varnode* varnodeOutput = nullptr;
				if(operandsCount >= 2)
					varnodeInput1 = requestOperandValue(m_curInstr->operands[1], size);
				if (operandsCount >= 3)
					varnodeInput2 = requestOperandValue(m_curInstr->operands[2], size);

				switch (mnemonic)
				{
				case ZYDIS_MNEMONIC_ADD:
				case ZYDIS_MNEMONIC_INC:
				case ZYDIS_MNEMONIC_DEC:
				{
					if (mnemonic == ZYDIS_MNEMONIC_INC || mnemonic == ZYDIS_MNEMONIC_SUB) {
						varnodeInput1 = new ConstantVarnode(0x1, size);
					}
					else {
						addMicroInstruction(InstructionId::INT_CARRY, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_CF));
					}
					addMicroInstruction(InstructionId::INT_SCARRY, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_OF));
					varnodeOutput = addGenericOperation(mnemonic == ZYDIS_MNEMONIC_SUB ? InstructionId::INT_SUB : InstructionId::INT_ADD, varnodeInput0, varnodeInput1, memLocVarnode);
					break;
				}

				case ZYDIS_MNEMONIC_SUB:
				case ZYDIS_MNEMONIC_CMP:
				{
					addMicroInstruction(InstructionId::INT_LESS, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_CF));
					addMicroInstruction(InstructionId::INT_SBORROW, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_OF));
					varnodeOutput = addGenericOperation(InstructionId::INT_SUB, varnodeInput0, varnodeInput1, memLocVarnode, mnemonic == ZYDIS_MNEMONIC_CMP);
					break;
				}

				case ZYDIS_MNEMONIC_NEG:
				{
					auto varnodeZero = new ConstantVarnode(0x0, size);
					addMicroInstruction(InstructionId::INT_NOTEQUAL, varnodeInput0, varnodeZero, CreateVarnode(ZYDIS_CPUFLAG_CF));
					addMicroInstruction(InstructionId::INT_SBORROW, varnodeZero, varnodeInput0, CreateVarnode(ZYDIS_CPUFLAG_OF));
					varnodeOutput = addGenericOperation(InstructionId::INT_2COMP, varnodeInput0, nullptr, memLocVarnode);
					break;
				}

				case ZYDIS_MNEMONIC_MUL:
				case ZYDIS_MNEMONIC_IMUL:
				{
					Varnode* varnodeDst = nullptr;
					Varnode* varnodeMul1;
					Varnode* varnodeMul2;
					Varnode* varnodeCF = CreateVarnode(ZYDIS_CPUFLAG_CF);

					if (operandsCount == 1) {
						varnodeDst = varnodeMul1 = CreateVarnode(GetRegisterBySize(ZYDIS_REGISTER_RAX, size));
						varnodeMul2 = varnodeInput0;
					}
					else if (operandsCount == 2) {
						varnodeDst = varnodeMul1 = varnodeInput0;
						varnodeMul2 = varnodeInput1;
					}
					else {
						varnodeDst = varnodeInput0;
						varnodeMul1 = varnodeInput1;
						varnodeMul2 = varnodeInput2;
					}

					auto instrExt = InstructionId::INT_ZEXT;
					if (mnemonic == ZYDIS_MNEMONIC_IMUL)
						instrExt = InstructionId::INT_SEXT;

					auto varnodeZext1 = new SymbolVarnode(size * 2);
					addMicroInstruction(instrExt, varnodeMul1, nullptr, varnodeZext1);
					auto varnodeZext2 = new SymbolVarnode(size * 2);
					addMicroInstruction(instrExt, varnodeMul2, nullptr, varnodeZext2);
					auto varnodeMult = new SymbolVarnode(size * 2);
					addMicroInstruction(InstructionId::INT_MULT, varnodeZext1, varnodeZext2, varnodeMult);

					Varnode* varnodeSubpiece;
					if (operandsCount == 1) {
						varnodeSubpiece = CreateVarnode(GetRegisterBySize(ZYDIS_REGISTER_RDX, size));
					}
					else {
						varnodeSubpiece = new SymbolVarnode(size * 2);
					}
					if (mnemonic == ZYDIS_MNEMONIC_IMUL) {
						addMicroInstruction(InstructionId::INT_MULT, varnodeMul1, varnodeMul2, varnodeDst);
						addMicroInstruction(InstructionId::SUBPIECE, varnodeMult, new ConstantVarnode(size, 0x4), varnodeSubpiece);
						auto varnodeNe1 = new SymbolVarnode(0x1);
						addMicroInstruction(InstructionId::INT_NOTEQUAL, varnodeSubpiece, new ConstantVarnode(0x0, size), varnodeNe1);
						auto varnode2Cmp = new SymbolVarnode(size);
						addMicroInstruction(InstructionId::INT_2COMP, new ConstantVarnode(0x1, size), nullptr, varnode2Cmp);
						auto varnodeNe2 = new SymbolVarnode(0x1);
						addMicroInstruction(InstructionId::INT_NOTEQUAL, varnodeSubpiece, varnode2Cmp, varnodeNe2);
						addMicroInstruction(InstructionId::INT_AND, varnodeNe1, varnodeNe2, varnodeCF);
					}
					else {
						addMicroInstruction(InstructionId::SUBPIECE, varnodeMult, new ConstantVarnode(size, 0x4), varnodeSubpiece);
						addMicroInstruction(InstructionId::SUBPIECE, varnodeMult, new ConstantVarnode(0x0, 0x4), varnodeDst);
						addMicroInstruction(InstructionId::INT_NOTEQUAL, varnodeSubpiece, new ConstantVarnode(0x0, size), varnodeCF);
					}

					addMicroInstruction(InstructionId::COPY, varnodeCF, nullptr, CreateVarnode(ZYDIS_CPUFLAG_OF));
					break;
				}

				case ZYDIS_MNEMONIC_DIV:
				case ZYDIS_MNEMONIC_IDIV:
				{
					auto instrExt = InstructionId::INT_ZEXT;
					auto instrDiv = InstructionId::INT_DIV;
					auto instrRem = InstructionId::INT_REM;
					if (mnemonic == ZYDIS_MNEMONIC_IMUL) {
						instrExt = InstructionId::INT_SEXT;
						instrDiv = InstructionId::INT_SDIV;
						instrRem = InstructionId::INT_SREM;
					}

					auto varnodeRax = CreateVarnode(GetRegisterBySize(ZYDIS_REGISTER_RAX, size));
					auto varnodeRdx = CreateVarnode(GetRegisterBySize(ZYDIS_REGISTER_RDX, size));
					auto varnodeExt = new SymbolVarnode(size * 2);
					addMicroInstruction(instrExt, varnodeInput0, nullptr, varnodeExt);

					auto varnodeZext1 = new SymbolVarnode(size * 2);
					addMicroInstruction(InstructionId::INT_ZEXT, varnodeRdx, nullptr, varnodeZext1);
					auto varnodeLeft = new SymbolVarnode(size * 2);
					addMicroInstruction(InstructionId::INT_LEFT, varnodeZext1, new ConstantVarnode(size * 0x8, 0x4), varnodeLeft);
					auto varnodeZext2 = new SymbolVarnode(size * 2);
					addMicroInstruction(InstructionId::INT_ZEXT, varnodeRax, nullptr, varnodeZext2);
					auto varnodeOr = new SymbolVarnode(size * 2);
					addMicroInstruction(InstructionId::INT_OR, varnodeLeft, varnodeZext2, varnodeOr);

					auto varnodeDiv = new SymbolVarnode(size * 2);
					addMicroInstruction(instrDiv, varnodeOr, varnodeExt, varnodeDiv);

					addMicroInstruction(InstructionId::SUBPIECE, varnodeDiv, new ConstantVarnode(0x0, 0x4), varnodeRax);
					auto varnodeRem = new SymbolVarnode(size * 2);
					addMicroInstruction(instrRem, varnodeOr, varnodeExt, varnodeRem);
					addMicroInstruction(InstructionId::SUBPIECE, varnodeRem, new ConstantVarnode(0x0, 0x4), varnodeRdx);
					break;
				}

				case ZYDIS_MNEMONIC_AND:
				case ZYDIS_MNEMONIC_TEST:
				case ZYDIS_MNEMONIC_OR:
				case ZYDIS_MNEMONIC_XOR:
				{
					auto instrId = InstructionId::NONE;
					switch (instrId) {
					case ZYDIS_MNEMONIC_AND:
					case ZYDIS_MNEMONIC_TEST:
						instrId = InstructionId::INT_AND;
						break;
					case ZYDIS_MNEMONIC_OR:
						instrId = InstructionId::INT_OR;
						break;
					case ZYDIS_MNEMONIC_XOR:
						instrId = InstructionId::INT_XOR;
						break;
					}
					addMicroInstruction(InstructionId::COPY, new ConstantVarnode(0x0, size), nullptr, CreateVarnode(ZYDIS_CPUFLAG_CF));
					addMicroInstruction(InstructionId::COPY, new ConstantVarnode(0x0, size), nullptr, CreateVarnode(ZYDIS_CPUFLAG_OF));
					varnodeOutput = addGenericOperation(instrId, varnodeInput0, varnodeInput1, memLocVarnode, mnemonic == ZYDIS_MNEMONIC_TEST);
					break;
				}

				case ZYDIS_MNEMONIC_SHL:
				case ZYDIS_MNEMONIC_SHR:
				case ZYDIS_MNEMONIC_SAR:
				{
					auto instrId = InstructionId::NONE;
					switch (instrId) {
					case ZYDIS_MNEMONIC_SHL:
						instrId = InstructionId::INT_LEFT;
						break;
					case ZYDIS_MNEMONIC_SHR:
						instrId = InstructionId::INT_RIGHT;
						break;
					case ZYDIS_MNEMONIC_SAR:
						instrId = InstructionId::INT_SRIGHT;
						break;
					}
					auto varnodeAndInput1 = new SymbolVarnode(0x8);
					addMicroInstruction(InstructionId::INT_AND, varnodeInput1, new ConstantVarnode(63, size), varnodeAndInput1);
					addGenericOperation(instrId, varnodeInput0, varnodeAndInput1, memLocVarnode);
					//flags ...
					break;
				}

				case ZYDIS_MNEMONIC_BT:
				case ZYDIS_MNEMONIC_BTR:
				{
					auto varnodeAndInput1 = new SymbolVarnode(0x8);
					addMicroInstruction(InstructionId::INT_AND, varnodeInput1, new ConstantVarnode(63, size), varnodeAndInput1);
					auto varnodeRight = new SymbolVarnode(0x8);
					addMicroInstruction(InstructionId::INT_RIGHT, varnodeInput0, varnodeAndInput1, varnodeRight);
					auto varnodeAnd = new SymbolVarnode(0x8);
					addMicroInstruction(InstructionId::INT_AND, varnodeRight, new ConstantVarnode(1, size), varnodeAnd);

					if (mnemonic != ZYDIS_MNEMONIC_BT) {
						auto varnodeLeft = new SymbolVarnode(0x8);
						addMicroInstruction(InstructionId::INT_LEFT, new ConstantVarnode(1, size), varnodeAndInput1, varnodeLeft);
						auto varnodeNegate = new SymbolVarnode(0x8);
						addMicroInstruction(InstructionId::INT_NEGATE, varnodeLeft, nullptr, varnodeNegate);
						addGenericOperation(InstructionId::INT_AND, varnodeInput0, varnodeNegate, memLocVarnode);
					}

					addMicroInstruction(InstructionId::INT_NOTEQUAL, varnodeAnd, new ConstantVarnode(0x0, size), CreateVarnode(ZYDIS_CPUFLAG_CF));
					break;
				}
				}

				if (varnodeOutput) {
					addMicroInstruction(InstructionId::INT_SLESS, varnodeOutput, new ConstantVarnode(0x0, size), CreateVarnode(ZYDIS_CPUFLAG_SF));
					addMicroInstruction(InstructionId::INT_EQUAL, varnodeOutput, new ConstantVarnode(0x0, size), CreateVarnode(ZYDIS_CPUFLAG_ZF));
				}
				break;
			}

			case ZYDIS_MNEMONIC_NOT:
			{
				Varnode* memLocVarnode = nullptr;
				auto varnodeInput0 = requestOperandValue(m_curInstr->operands[0], size, &memLocVarnode);
				addGenericOperation(InstructionId::INT_NEGATE, varnodeInput0, nullptr, memLocVarnode);
				break;
			}

			case ZYDIS_MNEMONIC_PUSH:
			{
				auto varnodeReg = requestOperandValue(m_curInstr->operands[0], size);
				auto varnodeRsp = CreateVarnode(ZYDIS_REGISTER_RSP);
				addMicroInstruction(InstructionId::INT_SUB, varnodeRsp, new ConstantVarnode(size, 0x8), varnodeRsp);
				addMicroInstruction(InstructionId::STORE, varnodeRsp, varnodeReg);
				break;
			}

			case ZYDIS_MNEMONIC_POP:
			{
				auto varnodeReg = requestOperandValue(m_curInstr->operands[0], size);
				auto varnodeRsp = CreateVarnode(ZYDIS_REGISTER_RSP);
				addMicroInstruction(InstructionId::LOAD, varnodeRsp, nullptr, varnodeReg);
				addMicroInstruction(InstructionId::INT_ADD, varnodeRsp, new ConstantVarnode(size, 0x8), varnodeRsp);
				break;
			}

			case ZYDIS_MNEMONIC_RET:
			{
				auto varnodeRip = CreateVarnode(ZYDIS_REGISTER_RIP);
				auto varnodeRsp = CreateVarnode(ZYDIS_REGISTER_RSP);
				addMicroInstruction(InstructionId::LOAD, varnodeRsp, nullptr, varnodeRip);
				addMicroInstruction(InstructionId::INT_ADD, varnodeRsp, new ConstantVarnode(size, 0x8), varnodeRsp);
				addMicroInstruction(InstructionId::RETURN, varnodeRip, nullptr);
				break;
			}

			case ZYDIS_MNEMONIC_JMP:
			case ZYDIS_MNEMONIC_CALL:
			{
				auto& operand = m_curInstr->operands[0];
				Varnode* varnodeInput0;
				if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
					int64_t targetOffset = getJumpOffsetByOperand(m_curInstr->operands[0]);
					varnodeInput0 = new ConstantVarnode((uint64_t&)targetOffset, 0x8);
				}
				else {
					varnodeInput0 = requestOperandValue(operand, size);
				}

				if (mnemonic == ZYDIS_MNEMONIC_JMP) {
					addMicroInstruction(InstructionId::BRANCH, varnodeInput0, nullptr);
				}
				else {
					if (false) {
						auto varnodeRsp = CreateVarnode(ZYDIS_REGISTER_RSP);
						addMicroInstruction(InstructionId::INT_SUB, varnodeRsp, new ConstantVarnode(0x8, 0x8), varnodeRsp);
						auto offset = getNextInstrOffset();
						addMicroInstruction(InstructionId::STORE, varnodeRsp, new ConstantVarnode((uint64_t&)offset, 0x8));
					}
					addMicroInstruction(InstructionId::CALL, varnodeInput0, nullptr);
				}
				break;
			}

			case ZYDIS_MNEMONIC_CMOVZ:
			case ZYDIS_MNEMONIC_CMOVNZ:
			case ZYDIS_MNEMONIC_CMOVL:
			case ZYDIS_MNEMONIC_CMOVLE:
			case ZYDIS_MNEMONIC_CMOVNL:
			case ZYDIS_MNEMONIC_CMOVNLE:
			{
				FlagCond flagCond = FlagCond::NONE;
				switch (mnemonic)
				{
				case ZYDIS_MNEMONIC_CMOVZ:
					flagCond = FlagCond::Z;
					break;
				case ZYDIS_MNEMONIC_CMOVNZ:
					flagCond = FlagCond::NZ;
					break;
				case ZYDIS_MNEMONIC_CMOVL:
					flagCond = FlagCond::L;
					break;
				case ZYDIS_MNEMONIC_CMOVLE:
					flagCond = FlagCond::LE;
					break;
				case ZYDIS_MNEMONIC_CMOVNL:
					flagCond = FlagCond::NL;
					break;
				case ZYDIS_MNEMONIC_CMOVNLE:
					flagCond = FlagCond::NLE;
					break;
				}

				auto varnodeFlagCond = GetFlagCondition(flagCond);
				auto varnodeNeg = new SymbolVarnode(1);
				addMicroInstruction(InstructionId::BOOL_NEGATE, varnodeFlagCond, nullptr, varnodeNeg);
				auto offset = getNextInstrOffset();
				auto varnodeNextInstrOffset = new ConstantVarnode((uint64_t&)offset, 0x8);
				addMicroInstruction(InstructionId::CBRANCH, varnodeNextInstrOffset, varnodeNeg);
				auto operand = m_curInstr->operands[1];
				auto varnode = requestOperandValue(operand, size, nullptr, operand.actions != 0);
				addGenericOperation(InstructionId::COPY, varnode, nullptr);
				break;
			}

			case ZYDIS_MNEMONIC_SETZ:
			case ZYDIS_MNEMONIC_SETNZ:
			case ZYDIS_MNEMONIC_SETL:
			case ZYDIS_MNEMONIC_SETLE:
			case ZYDIS_MNEMONIC_SETNL:
			case ZYDIS_MNEMONIC_SETNLE:
			{
				FlagCond flagCond = FlagCond::NONE;
				switch (mnemonic)
				{
				case ZYDIS_MNEMONIC_SETZ:
					flagCond = FlagCond::Z;
					break;
				case ZYDIS_MNEMONIC_SETNZ:
					flagCond = FlagCond::NZ;
					break;
				case ZYDIS_MNEMONIC_SETL:
					flagCond = FlagCond::L;
					break;
				case ZYDIS_MNEMONIC_SETLE:
					flagCond = FlagCond::LE;
					break;
				case ZYDIS_MNEMONIC_SETNL:
					flagCond = FlagCond::NL;
					break;
				case ZYDIS_MNEMONIC_SETNLE:
					flagCond = FlagCond::NLE;
					break;
				}

				auto varnodeFlagCond = GetFlagCondition(flagCond);
				addGenericOperation(InstructionId::COPY, varnodeFlagCond, nullptr);
				break;
			}

			case ZYDIS_MNEMONIC_JZ:
			case ZYDIS_MNEMONIC_JNZ:
			case ZYDIS_MNEMONIC_JL:
			case ZYDIS_MNEMONIC_JLE:
			case ZYDIS_MNEMONIC_JNLE:
			case ZYDIS_MNEMONIC_JNBE:
			case ZYDIS_MNEMONIC_JNL:
			case ZYDIS_MNEMONIC_JNB:
			{
				FlagCond flagCond = FlagCond::NONE;
				switch (mnemonic)
				{
				case ZYDIS_MNEMONIC_JZ:
					flagCond = FlagCond::Z;
					break;
				case ZYDIS_MNEMONIC_JNZ:
					flagCond = FlagCond::NZ;
					break;
				case ZYDIS_MNEMONIC_JL:
					flagCond = FlagCond::L;
					break;
				case ZYDIS_MNEMONIC_JLE:
					flagCond = FlagCond::LE;
					break;
				case ZYDIS_MNEMONIC_JNL:
				case ZYDIS_MNEMONIC_JNB:
					flagCond = FlagCond::NL;
					break;
				case ZYDIS_MNEMONIC_JNLE:
				case ZYDIS_MNEMONIC_JNBE:
					flagCond = FlagCond::NLE;
					break;
				}

				auto varnodeFlagCond = GetFlagCondition(flagCond);
				int64_t targetOffset = getJumpOffsetByOperand(m_curInstr->operands[0]);
				auto varnodeNextInstrOffset = new ConstantVarnode((uint64_t&)targetOffset, 0x8);
				addMicroInstruction(InstructionId::CBRANCH, varnodeNextInstrOffset, varnodeFlagCond);
				break;
			}

			
			}
		}

		int64_t getJumpOffsetByOperand(const ZydisDecodedOperand& operand) {
			auto offset = (int64_t)m_curInstr->length +
				(operand.imm.is_signed ? (m_curOffset + (int)operand.imm.value.s) : (m_curOffset + (unsigned int)operand.imm.value.u));
			return offset << 8;
		}

		int64_t getNextInstrOffset() {
			auto offset = (int64_t)m_curOffset + m_curInstr->length;
			return offset << 8;
		}

		Varnode* addGenericOperation(InstructionId instrId, Varnode* varnodeInput0, Varnode* varnodeInput1, Varnode* memLocVarnode = nullptr, bool isFictitious = false) {
			auto& operand = m_curInstr->operands[0];
			auto size = operand.size / 0x8;
			Varnode* varnodeOutput = nullptr;
			if (!isFictitious && operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
				varnodeOutput = CreateVarnode(operand.reg.value);
			} else {
				varnodeOutput = new SymbolVarnode(size);
			}

			addMicroInstruction(instrId, varnodeInput0, varnodeInput1, varnodeOutput);

			if (!isFictitious && operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
				setDestinationMemOperand(operand, size, varnodeOutput, memLocVarnode);
			}

			return varnodeOutput;
		}

		void addMicroInstruction(InstructionId id, Varnode* input0, Varnode* input1 = nullptr, Varnode* output = nullptr, bool zext = true) {
			auto instr = new Instruction(id, input0, input1, output, m_curOffset, m_curInstr->length, m_curOrderId++);
			if (m_curOrderId == 1) { //for debug info
				ZydisFormatter formatter;
				ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
				char buffer[256];
				ZydisFormatterFormatInstruction(&formatter, m_curInstr, buffer, sizeof(buffer),
					m_curAddr);
				instr->m_originalView = buffer;
			}
			m_result.push_back(instr);
			if (zext) {
				if (auto outputReg = dynamic_cast<RegisterVarnode*>(output)) {
					if (outputReg->m_register.m_valueRangeMask == 0xFFFFFFFF) { //TODO: не везде -> imul
						auto extReg = outputReg->m_register;
						extReg.m_valueRangeMask = 0xFFFFFFFFFFFFFFFF;
						addMicroInstruction(InstructionId::INT_ZEXT, outputReg, nullptr, new RegisterVarnode(extReg));
					}
				}
			}
		}

		void setDestinationMemOperand(const ZydisDecodedOperand& operand, int size, Varnode* varnode, Varnode* memLocVarnode = nullptr) {
			if (!memLocVarnode) {
				memLocVarnode = requestOperandValue(operand, size, nullptr, false);
			}
			addMicroInstruction(InstructionId::STORE, memLocVarnode, varnode);
		}

		Varnode* requestOperandValue(const ZydisDecodedOperand& operand, int size, Varnode** memLocVarnode = nullptr, bool isMemLocLoaded = true) {
			if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
				return CreateVarnode(operand.reg.value);
			}
			else if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				return new ConstantVarnode(operand.imm.value.u & GetMaskBySize(size), size);
			}
			else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
				Varnode* resultVarnode = nullptr;
				RegisterVarnode* baseRegVarnode = nullptr;

				if (operand.mem.base != ZYDIS_REGISTER_NONE) {
					baseRegVarnode = CreateVarnode(operand.mem.base);
				}

				if (operand.mem.index != ZYDIS_REGISTER_NONE) {
					resultVarnode = CreateVarnode(operand.mem.index);
					if (operand.mem.scale != 1) {
						auto symbolVarnode = new SymbolVarnode(0x8);
						addMicroInstruction(InstructionId::INT_MULT, resultVarnode, new ConstantVarnode(operand.mem.scale, 0x8), symbolVarnode);
						resultVarnode = symbolVarnode;
					}
					if (baseRegVarnode != nullptr) {
						auto symbolVarnode = new SymbolVarnode(0x8);
						addMicroInstruction(InstructionId::INT_ADD, baseRegVarnode, resultVarnode, symbolVarnode);
						resultVarnode = symbolVarnode;
					}
				}
				else {
					resultVarnode = baseRegVarnode;
				}

				if (operand.mem.disp.has_displacement) {
					auto dispVarnode = new ConstantVarnode((uint64_t&)operand.mem.disp.value, 0x8);
					if (resultVarnode != nullptr) {
						auto symbolVarnode = new SymbolVarnode(0x8);
						addMicroInstruction(InstructionId::INT_ADD, resultVarnode, dispVarnode, symbolVarnode);
						resultVarnode = symbolVarnode;
					}
					else {
						resultVarnode = dispVarnode;
					}
				}

				if (memLocVarnode) {
					*memLocVarnode = resultVarnode;
				}

				if (isMemLocLoaded) { //check for LEA instruction
					auto symbolVarnode = new SymbolVarnode(0x8);
					addMicroInstruction(InstructionId::LOAD, resultVarnode, nullptr, symbolVarnode);
					resultVarnode = symbolVarnode;
				}
				return resultVarnode;
			}
			return nullptr;
		}

		Varnode* GetFlagCondition(FlagCond flagCond) {
			Varnode* varnodeCond = nullptr;

			switch (flagCond)
			{
			case FlagCond::Z:
			case FlagCond::NZ:
			{
				varnodeCond = CreateVarnode(ZYDIS_CPUFLAG_ZF);
				if (flagCond == FlagCond::NZ) {
					auto varnodeNeg = new SymbolVarnode(1);
					addMicroInstruction(InstructionId::BOOL_NEGATE, varnodeCond, nullptr, varnodeNeg);
					varnodeCond = varnodeNeg;
				}
				break;
			}
			case FlagCond::L:
			case FlagCond::LE:
			{
				auto varnodeNe = new SymbolVarnode(1);
				addMicroInstruction(InstructionId::INT_NOTEQUAL, CreateVarnode(ZYDIS_CPUFLAG_OF), CreateVarnode(ZYDIS_CPUFLAG_SF), varnodeNe);
				if (flagCond == FlagCond::LE) {
					auto varnodeOr = new SymbolVarnode(1);
					addMicroInstruction(InstructionId::BOOL_OR, CreateVarnode(ZYDIS_CPUFLAG_ZF), varnodeNe, varnodeOr);
					varnodeCond = varnodeOr;
				}
				else {
					varnodeCond = varnodeNe;
				}
				break;
			}
			case FlagCond::NL:
			case FlagCond::NLE:
			{
				auto varnodeEq = new SymbolVarnode(1);
				addMicroInstruction(InstructionId::INT_EQUAL, CreateVarnode(ZYDIS_CPUFLAG_OF), CreateVarnode(ZYDIS_CPUFLAG_SF), varnodeEq);
				if (flagCond == FlagCond::LE) {
					auto varnodeNeg = new SymbolVarnode(1);
					addMicroInstruction(InstructionId::BOOL_NEGATE, CreateVarnode(ZYDIS_CPUFLAG_ZF), nullptr, varnodeNeg);
					auto varnodeAnd = new SymbolVarnode(1);
					addMicroInstruction(InstructionId::BOOL_AND, varnodeEq, varnodeNeg, varnodeAnd);
					varnodeCond = varnodeAnd;
				}
				else {
					varnodeCond = varnodeEq;
				}
				break;
			}
			}

			return varnodeCond;
		}

		int getFirstExplicitOperandsCount() {
			int result = 0;
			while (result < m_curInstr->operand_count) {
				if (m_curInstr->operands[result].visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
					break;
				result++;
			}
			return result;
		}

		static ZydisRegister GetRegisterBySize(ZydisRegister reg, int size) {
			int idx = reg - ZYDIS_REGISTER_RAX;
			switch (size)
			{
			case 1:
				return ZydisRegister(ZYDIS_REGISTER_AL + idx + (idx >= 3 ? 4 : 0));
			case 2:
				return ZydisRegister(ZYDIS_REGISTER_AX + idx);
			case 4:
				return ZydisRegister(ZYDIS_REGISTER_EAX + idx);
			case 8:
				return ZydisRegister(ZYDIS_REGISTER_RAX + idx);
			}
			return ZYDIS_REGISTER_NONE;
		}
		
		static Register CreateRegister(ZydisRegister reg) {
			if (reg >= ZYDIS_REGISTER_AL && reg <= ZYDIS_REGISTER_BL) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AL, 0xFF, false);
			}
			else if (reg >= ZYDIS_REGISTER_AH && reg <= ZYDIS_REGISTER_BH) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AH, 0xFF00, false);
			}
			else if (reg >= ZYDIS_REGISTER_SPL && reg <= ZYDIS_REGISTER_R15B) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AH, 0xFF, false);
			}
			else if (reg >= ZYDIS_REGISTER_AX && reg <= ZYDIS_REGISTER_R15W) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AX, 0xFFFF, false);
			}
			else if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_EAX, 0xFFFFFFFF, false);
			}
			else if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15) {
				return Register(reg, 0xFFFFFFFFFFFFFFFF, false);
			}
			else if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31) {
				return Register(ZYDIS_REGISTER_ZMM0 + reg - ZYDIS_REGISTER_XMM0, 0xFFFF, true);
			}
			else if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31) {
				return Register(ZYDIS_REGISTER_ZMM0 + reg - ZYDIS_REGISTER_YMM0, 0xFFFFFFFF, true);
			}
			else if (reg >= ZYDIS_REGISTER_ZMM0 && reg <= ZYDIS_REGISTER_ZMM31) {
				return Register(reg, 0xFFFFFFFFFFFFFFFF, true);
			}

			return Register();
		}

		static Register CreateFlagRegister(ZydisCPUFlag flag) {
			auto mask = (uint64_t)1 << flag;
			return Register(ZYDIS_REGISTER_RFLAGS, mask, false);
		}

		static RegisterVarnode* CreateVarnode(ZydisRegister reg) {
			return new RegisterVarnode(CreateRegister(reg));
		}

		static RegisterVarnode* CreateVarnode(ZydisCPUFlag flag) {
			return new RegisterVarnode(CreateFlagRegister(flag));
		}
	};
};