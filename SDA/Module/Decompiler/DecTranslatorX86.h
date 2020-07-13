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
		Instruction* m_curTrInstr;
		ZydisDecodedInstruction* m_curInstr;

		void translateInstruction(int offset, ZydisDecodedInstruction& instr) {
			m_curInstr = &instr;
			translateCurInstruction();
			m_result.insert(std::make_pair(offset, m_curTrInstr));
		}

		void translateCurInstruction() {
			m_curTrInstr = new Instruction;
			auto mnemonic = m_curInstr->mnemonic;
			auto size = m_curInstr->operands[0].size / 8;
			auto operandsCount = getFirstExplicitOperandsCount();
			
			switch (mnemonic)
			{
			case ZYDIS_MNEMONIC_MOV:
			case ZYDIS_MNEMONIC_MOVZX:
			case ZYDIS_MNEMONIC_MOVSX:
			case ZYDIS_MNEMONIC_MOVSXD:
			case ZYDIS_MNEMONIC_LEA:
			{
				auto operand = m_curInstr->operands[1];
				auto varnode = requestOperandValue(operand, nullptr, operand.actions != 0);
				addGenericOperation(MicroInstruction::COPY, varnode, nullptr);
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
				Varnode* varnodeInput0 = requestOperandValue(m_curInstr->operands[0], &memLocVarnode);
				Varnode* varnodeInput1 = nullptr;
				Varnode* varnodeInput2 = nullptr;
				Varnode* varnodeOutput = nullptr;
				if(operandsCount >= 1)
					varnodeInput1 = requestOperandValue(m_curInstr->operands[1]);
				if (operandsCount >= 2)
					varnodeInput2 = requestOperandValue(m_curInstr->operands[2]);

				switch (mnemonic)
				{
				case ZYDIS_MNEMONIC_ADD:
				case ZYDIS_MNEMONIC_INC:
				case ZYDIS_MNEMONIC_DEC:
					if (mnemonic == ZYDIS_MNEMONIC_INC || mnemonic == ZYDIS_MNEMONIC_SUB) {
						varnodeInput1 = new ConstantVarnode(0x1, size);
					} else {
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_CARRY, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_CF));
					}
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_SCARRY, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_OF));
					varnodeOutput = addGenericOperation(mnemonic == ZYDIS_MNEMONIC_SUB ? MicroInstruction::INT_SUB : MicroInstruction::INT_ADD, varnodeInput0, varnodeInput1, memLocVarnode);
					break;

				case ZYDIS_MNEMONIC_SUB:
				case ZYDIS_MNEMONIC_CMP:
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_LESS, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_CF));
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_SBORROW, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_OF));
					varnodeOutput = addGenericOperation(MicroInstruction::INT_SUB, varnodeInput0, varnodeInput1, memLocVarnode, mnemonic == ZYDIS_MNEMONIC_CMP);
					break;

				case ZYDIS_MNEMONIC_NEG:
					auto varnodeZero = new ConstantVarnode(0x0, size);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_NOTEQUAL, varnodeInput0, varnodeZero, CreateVarnode(ZYDIS_CPUFLAG_CF));
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_SBORROW, varnodeZero, varnodeInput0, CreateVarnode(ZYDIS_CPUFLAG_OF));
					varnodeOutput = addGenericOperation(MicroInstruction::INT_2COMP, varnodeInput0, nullptr, memLocVarnode);
					break;

				case ZYDIS_MNEMONIC_MUL:
				case ZYDIS_MNEMONIC_IMUL:
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

					auto instrExt = MicroInstruction::INT_ZEXT;
					if (mnemonic == ZYDIS_MNEMONIC_IMUL)
						instrExt = MicroInstruction::INT_SEXT;

					auto varnodeZext1 = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(instrExt, varnodeMul1, nullptr, varnodeZext1);
					auto varnodeZext2 = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(instrExt, varnodeMul2, nullptr, varnodeZext2);
					auto varnodeMult = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_MULT, varnodeZext1, varnodeZext2, varnodeMult);

					Varnode* varnodeSubpiece;
					if (operandsCount == 1) {
						varnodeSubpiece = CreateVarnode(GetRegisterBySize(ZYDIS_REGISTER_RDX, size));
					}
					else {
						varnodeSubpiece = new SymbolVarnode(size * 2);
					}
					if (mnemonic == ZYDIS_MNEMONIC_IMUL) {
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_MULT, varnodeMul1, varnodeMul2, varnodeDst);
						m_curTrInstr->addMicroInstruction(MicroInstruction::SUBPIECE, varnodeMult, new ConstantVarnode(size, 0x4), varnodeSubpiece);
						auto varnodeNe1 = new SymbolVarnode(0x1);
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_NOTEQUAL, varnodeSubpiece, new ConstantVarnode(0x0, size), varnodeNe1);
						auto varnode2Cmp = new SymbolVarnode(size);
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_2COMP, new ConstantVarnode(0x1, size), nullptr, varnode2Cmp);
						auto varnodeNe2 = new SymbolVarnode(0x1);
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_NOTEQUAL, varnodeSubpiece, varnode2Cmp, varnodeNe2);
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_AND, varnodeNe1, varnodeNe2, varnodeCF);
					}
					else {
						m_curTrInstr->addMicroInstruction(MicroInstruction::SUBPIECE, varnodeMult, new ConstantVarnode(size, 0x4), varnodeSubpiece);
						m_curTrInstr->addMicroInstruction(MicroInstruction::SUBPIECE, varnodeMult, new ConstantVarnode(0x0, 0x4), varnodeDst);
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_NOTEQUAL, varnodeSubpiece, new ConstantVarnode(0x0, size), varnodeCF);
					}
					
					m_curTrInstr->addMicroInstruction(MicroInstruction::COPY, varnodeCF, nullptr, CreateVarnode(ZYDIS_CPUFLAG_OF));
					break;

				case ZYDIS_MNEMONIC_DIV:
				case ZYDIS_MNEMONIC_IDIV:
					auto instrExt = MicroInstruction::INT_ZEXT;
					auto instrDiv = MicroInstruction::INT_DIV;
					auto instrRem = MicroInstruction::INT_REM;
					if (mnemonic == ZYDIS_MNEMONIC_IMUL) {
						instrExt = MicroInstruction::INT_SEXT;
						instrDiv = MicroInstruction::INT_SDIV;
						instrRem = MicroInstruction::INT_SREM;
					}

					auto varnodeRax = CreateVarnode(GetRegisterBySize(ZYDIS_REGISTER_RAX, size));
					auto varnodeRdx = CreateVarnode(GetRegisterBySize(ZYDIS_REGISTER_RDX, size));
					auto varnodeExt = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(instrExt, varnodeInput0, nullptr, varnodeExt);
					
					auto varnodeZext1 = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_ZEXT, varnodeRdx, nullptr, varnodeZext1);
					auto varnodeLeft = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_LEFT, varnodeZext1, new ConstantVarnode(size * 0x8, 0x4), varnodeLeft);
					auto varnodeZext2 = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_ZEXT, varnodeRax, nullptr, varnodeZext2);
					auto varnodeOr = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_OR, varnodeLeft, varnodeZext2, varnodeOr);
					
					auto varnodeDiv = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(instrDiv, varnodeOr, varnodeExt, varnodeDiv);
					
					m_curTrInstr->addMicroInstruction(MicroInstruction::SUBPIECE, varnodeDiv, new ConstantVarnode(0x0, 0x4), varnodeRax);
					auto varnodeRem = new SymbolVarnode(size * 2);
					m_curTrInstr->addMicroInstruction(instrRem, varnodeOr, varnodeExt, varnodeRem);
					m_curTrInstr->addMicroInstruction(MicroInstruction::SUBPIECE, varnodeRem, new ConstantVarnode(0x0, 0x4), varnodeRdx);
					break;

				case ZYDIS_MNEMONIC_AND:
				case ZYDIS_MNEMONIC_TEST:
				case ZYDIS_MNEMONIC_OR:
				case ZYDIS_MNEMONIC_XOR:
					auto instrId = MicroInstruction::NONE;
					switch (instrId) {
					case ZYDIS_MNEMONIC_AND:
					case ZYDIS_MNEMONIC_TEST:
						instrId = MicroInstruction::INT_AND;
						break;
					case ZYDIS_MNEMONIC_OR:
						instrId = MicroInstruction::INT_OR;
						break;
					case ZYDIS_MNEMONIC_XOR:
						instrId = MicroInstruction::INT_XOR;
						break;
					}
					m_curTrInstr->addMicroInstruction(MicroInstruction::COPY, new ConstantVarnode(0x0, size), nullptr, CreateVarnode(ZYDIS_CPUFLAG_CF));
					m_curTrInstr->addMicroInstruction(MicroInstruction::COPY, new ConstantVarnode(0x0, size), nullptr, CreateVarnode(ZYDIS_CPUFLAG_OF));
					varnodeOutput = addGenericOperation(instrId, varnodeInput0, varnodeInput1, memLocVarnode, mnemonic == ZYDIS_MNEMONIC_TEST);
					break;

				case ZYDIS_MNEMONIC_SHL:
				case ZYDIS_MNEMONIC_SHR:
				case ZYDIS_MNEMONIC_SAR:
					auto instrId = MicroInstruction::NONE;
					switch (instrId) {
					case ZYDIS_MNEMONIC_SHL:
						instrId = MicroInstruction::INT_LEFT;
						break;
					case ZYDIS_MNEMONIC_SHR:
						instrId = MicroInstruction::INT_RIGHT;
						break;
					case ZYDIS_MNEMONIC_SAR:
						instrId = MicroInstruction::INT_SRIGHT;
						break;
					}
					auto varnodeAndInput1 = new SymbolVarnode(0x8);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_AND, varnodeInput1, new ConstantVarnode(63, size), varnodeAndInput1);
					addGenericOperation(instrId, varnodeInput0, varnodeAndInput1, memLocVarnode);
					//flags ...
					break;

				case ZYDIS_MNEMONIC_BT:
				case ZYDIS_MNEMONIC_BTR:
					auto varnodeAndInput1 = new SymbolVarnode(0x8);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_AND, varnodeInput1, new ConstantVarnode(63, size), varnodeAndInput1);
					auto varnodeRight = new SymbolVarnode(0x8);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_RIGHT, varnodeInput0, varnodeAndInput1, varnodeRight);
					auto varnodeAnd = new SymbolVarnode(0x8);
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_AND, varnodeRight, new ConstantVarnode(1, size), varnodeAnd);
					
					if (mnemonic != ZYDIS_MNEMONIC_BT) {
						auto varnodeLeft = new SymbolVarnode(0x8);
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_LEFT, new ConstantVarnode(1, size), varnodeAndInput1, varnodeLeft);
						auto varnodeNegate = new SymbolVarnode(0x8);
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_NEGATE, varnodeLeft, nullptr, varnodeNegate);
						addGenericOperation(MicroInstruction::INT_AND, varnodeInput0, varnodeNegate, memLocVarnode);
					}

					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_NOTEQUAL, varnodeAnd, new ConstantVarnode(0x0, size), CreateVarnode(ZYDIS_CPUFLAG_CF));
					break;
				}

				if (varnodeOutput) {
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_SLESS, varnodeOutput, new ConstantVarnode(0x0, size), CreateVarnode(ZYDIS_CPUFLAG_SF));
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_EQUAL, varnodeOutput, new ConstantVarnode(0x0, size), CreateVarnode(ZYDIS_CPUFLAG_ZF));
				}
				break;
			}

			case ZYDIS_MNEMONIC_NOT:
			{
				Varnode* memLocVarnode = nullptr;
				auto varnodeInput0 = requestOperandValue(m_curInstr->operands[0], &memLocVarnode);
				addGenericOperation(MicroInstruction::INT_NEGATE, varnodeInput0, nullptr, memLocVarnode);
				break;
			}
			}
		}

		Varnode* addGenericOperation(MicroInstruction::Id instrId, Varnode* varnodeInput0, Varnode* varnodeInput1, Varnode* memLocVarnode = nullptr, bool isFictitious = false) {
			auto& operand = m_curInstr->operands[0];
			Varnode* varnodeOutput = nullptr;
			if (!isFictitious && operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
				varnodeOutput = CreateVarnode(operand.reg.value);
			} else {
				varnodeOutput = new SymbolVarnode(0x8);
			}

			m_curTrInstr->addMicroInstruction(instrId, varnodeInput0, varnodeInput1, varnodeOutput);

			if (!isFictitious && operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
				setDestinationMemOperand(operand, varnodeOutput, memLocVarnode);
			}

			return varnodeOutput;
		}

		void addMicroInstruction(MicroInstruction::Id id, Varnode* input0, Varnode* input1 = nullptr, Varnode* output = nullptr) {
			m_curTrInstr->addMicroInstruction(id, input0, input1, output);
			if (auto outputReg = dynamic_cast<RegisterVarnode*>(output)) {
				if (outputReg->m_register.isZextNeeded()) { //TODO: не везде -> imul
					auto extReg = outputReg->m_register;
					extReg.m_valueRangeMask = extReg.m_actionRangeMask;
					m_curTrInstr->addMicroInstruction(MicroInstruction::INT_ZEXT, outputReg, nullptr, new RegisterVarnode(extReg));
				}
			}
		}

		void setDestinationMemOperand(const ZydisDecodedOperand& operand, Varnode* varnode, Varnode* memLocVarnode = nullptr) {
			if (!memLocVarnode) {
				memLocVarnode = requestOperandValue(operand, nullptr, false);
			}
			m_curTrInstr->addMicroInstruction(MicroInstruction::STORE, memLocVarnode, varnode);
		}

		Varnode* requestOperandValue(const ZydisDecodedOperand& operand, Varnode** memLocVarnode = nullptr, bool isMemLocLoaded = true) {
			if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
				return CreateVarnode(operand.reg.value);
			}
			else if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				auto size = operand.size / 0x8;
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
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_MULT, resultVarnode, new ConstantVarnode(operand.mem.scale, 0x8), symbolVarnode);
						resultVarnode = symbolVarnode;
					}
					if (baseRegVarnode != nullptr) {
						auto symbolVarnode = new SymbolVarnode(0x8);
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_ADD, baseRegVarnode, resultVarnode, symbolVarnode);
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
						m_curTrInstr->addMicroInstruction(MicroInstruction::INT_ADD, resultVarnode, dispVarnode, symbolVarnode);
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
					m_curTrInstr->addMicroInstruction(MicroInstruction::LOAD, resultVarnode, nullptr, symbolVarnode);
					resultVarnode = symbolVarnode;
				}
				return resultVarnode;
			}
			return nullptr;
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
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AL, 0xFF, 0xFF, false, reg);
			}
			else if (reg >= ZYDIS_REGISTER_AH && reg <= ZYDIS_REGISTER_BH) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AH, 0xFF00, 0xFF00, false, reg);
			}
			else if (reg >= ZYDIS_REGISTER_SPL && reg <= ZYDIS_REGISTER_R15B) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AH, 0xFF, 0xFF, false, reg);
			}
			else if (reg >= ZYDIS_REGISTER_AX && reg <= ZYDIS_REGISTER_R15W) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_AX, 0xFFFF, 0xFFFF, false, reg);
			}
			else if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D) {
				return Register(ZYDIS_REGISTER_RAX + reg - ZYDIS_REGISTER_EAX, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, false, reg);
			}
			else if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15) {
				return Register(reg, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, false, reg);
			}
			else if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31) {
				return Register(ZYDIS_REGISTER_ZMM0 + reg - ZYDIS_REGISTER_XMM0, 0xFFFF, 0xFFFF, true, reg);
			}
			else if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31) {
				return Register(ZYDIS_REGISTER_ZMM0 + reg - ZYDIS_REGISTER_YMM0, 0xFFFFFFFF, 0xFFFFFFFF, true, reg);
			}
			else if (reg >= ZYDIS_REGISTER_ZMM0 && reg <= ZYDIS_REGISTER_ZMM31) {
				return Register(reg, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, true, reg);
			}

			return Register();
		}

		static Register CreateFlagRegister(ZydisCPUFlag flag) {
			auto mask = (uint64_t)1 << flag;
			return Register(ZYDIS_REGISTER_RFLAGS, mask, mask, false);
		}

		static RegisterVarnode* CreateVarnode(ZydisRegister reg) {
			return new RegisterVarnode(CreateRegister(reg));
		}

		static RegisterVarnode* CreateVarnode(ZydisCPUFlag flag) {
			return new RegisterVarnode(CreateFlagRegister(flag));
		}
	};
};