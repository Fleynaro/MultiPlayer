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
			auto size = m_curInstr->operands[0].size / 8;
			
			switch (m_curInstr->mnemonic)
			{
			case ZYDIS_MNEMONIC_MOV:
			case ZYDIS_MNEMONIC_MOVZX:
			case ZYDIS_MNEMONIC_MOVSX:
			case ZYDIS_MNEMONIC_MOVSXD:
			case ZYDIS_MNEMONIC_LEA: {
				auto operand = m_curInstr->operands[1];
				auto varnode = requestOperandValue(operand, nullptr, operand.actions != 0);
				setDestinationOperand(varnode);
				//eax-rax
				break;
			}

			case ZYDIS_MNEMONIC_ADD:
				Varnode* memLocVarnode = nullptr;
				auto varnodeInput0 = requestOperandValue(m_curInstr->operands[0], &memLocVarnode);
				auto varnodeInput1 = requestOperandValue(m_curInstr->operands[1]);
				auto varnodeOutput = new SymbolVarnode(0x8);
				m_curTrInstr->addMicroInstruction(MicroInstruction::INT_ADD, varnodeInput0, varnodeInput1, varnodeOutput);

				m_curTrInstr->addMicroInstruction(MicroInstruction::INT_CARRY, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_CF));
				m_curTrInstr->addMicroInstruction(MicroInstruction::INT_SCARRY, varnodeInput0, varnodeInput1, CreateVarnode(ZYDIS_CPUFLAG_OF));
				setDestinationOperand(varnodeOutput, memLocVarnode);
				m_curTrInstr->addMicroInstruction(MicroInstruction::INT_SLESS, varnodeInput0, new ConstantVarnode(0x0, size), CreateVarnode(ZYDIS_CPUFLAG_SF));
				m_curTrInstr->addMicroInstruction(MicroInstruction::INT_EQUAL, varnodeInput0, new ConstantVarnode(0x0, size), CreateVarnode(ZYDIS_CPUFLAG_ZF));
				break;
			}
		}

		void setDestinationOperand(Varnode* varnode, Varnode* memLocVarnode = nullptr) {
			auto& operand = m_curInstr->operands[0];
			if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
				m_curTrInstr->addMicroInstruction(MicroInstruction::COPY, varnode, nullptr, CreateVarnode(operand.reg.value));
			}
			else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
				if (!memLocVarnode) {
					memLocVarnode = requestOperandValue(operand, nullptr, false);
				}
				m_curTrInstr->addMicroInstruction(MicroInstruction::STORE, memLocVarnode, varnode);
			}
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