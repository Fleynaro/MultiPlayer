#pragma once

#include "main.h"
#include <inttypes.h>


#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>


namespace CE
{
	namespace Disassembler
	{
		namespace Code
		{
			class Operand
			{
			public:
				enum Type {
					Register,
					Constant,
					Pointer
				};

				Operand() = default;

				Operand(ZydisRegister reg)
					: m_register(reg)
				{
					m_type = Register;
				}

				Operand(ZydisRegister reg, uint64_t offset)
					: m_register(reg), m_offset(offset)
				{
					m_type = Pointer;
				}

				Operand(uint64_t value)
					: m_offset(value)
				{
					m_type = Constant;
				}

				Type getType() {
					return m_type;
				}

				void* getLocationAddress() {
					return (void*)m_offset;
				}

				ZydisRegister getRegister() {
					return m_register;
				}

				uint64_t getOffset() {
					return m_offset;
				}
			private:
				Type m_type = Constant;
				ZydisRegister m_register = ZYDIS_REGISTER_NONE;
				uint64_t m_offset = 0;
			};

			class Instruction
			{
			public:
				virtual ZydisMnemonic_ getMnemonicId() = 0;
				virtual bool isGeneric() {
					return false;
				}
			};

			namespace Instructions
			{
				template<int operandCount>
				class AbstractInstructionWithOperands
				{
				public:
					AbstractInstructionWithOperands() = default;
					
					Operand& getOperand(int idx) {
						return m_operands[idx];
					}

					void setOperand(int idx, const Operand& operand) {
						m_operands[idx] = operand;;
					}
				protected:
					Operand m_operands[operandCount];
				};

				class Call : public Instruction, public AbstractInstructionWithOperands<1>
				{
				public:
					Call(Operand location)
					{
						setOperand(0, location);
					}

					ZydisMnemonic_ getMnemonicId() override {
						return ZYDIS_MNEMONIC_CALL;
					}

					bool hasAbsoluteAddr() {
						return getOperand(0).getType() == Code::Operand::Constant;
					}

					void* getAbsoluteAddr() {
						return getOperand(0).getLocationAddress();
					}
				};

				class Generic : public Instruction
				{
				public:
					Generic(ZydisMnemonic_ mnemonicId)
						: m_mnemonicId(mnemonicId)
					{}

					ZydisMnemonic_ getMnemonicId() override {
						return m_mnemonicId;
					}

					bool isGeneric() override {
						return true;
					}

					virtual void* getAbsoluteAddr() {
						return nullptr;
					}
				private:
					ZydisMnemonic_ m_mnemonicId;
				};

				class GenericWithOperands : public Generic, public AbstractInstructionWithOperands<2>
				{
				public:
					GenericWithOperands(ZydisMnemonic_ mnemonicId, int operandCount)
						: Generic(mnemonicId), m_operandCount(operandCount)
					{}

					void* getAbsoluteAddr() override {
						for (int i = 0; i < m_operandCount; i++) {
							if (getOperand(i).getType() == Code::Operand::Constant) {
								return getOperand(i).getLocationAddress();
							}
						}
						return nullptr;
					}

				private:
					int m_operandCount;
				};
			};
		};

		class Decoder
		{
		public:
			Decoder(void* startAddr, int size)
				: m_startAddr(startAddr), m_size(size)
			{}

			void decode(const std::function<bool(Code::Instruction&)>& callback)
			{
				ZydisDecoder decoder;
				ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

				ZyanUSize offset = 0;
				ZyanU64 runtime_address = (ZyanU64)m_startAddr;
				ZydisDecodedInstruction instruction;
				while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)runtime_address, getSize() - offset,
					&instruction)))
				{
					offset += instruction.length;
					runtime_address += instruction.length;

					doCallback(instruction, callback, runtime_address);
				}
			}

			int getSize() {
				return m_size;
			}
		private:
			void* m_startAddr;
			int m_size;

			void doCallback(const ZydisDecodedInstruction& instruction, const std::function<bool(Code::Instruction&)>& callback, ZyanU64 runtime_address)
			{
				switch(instruction.mnemonic)
				{
				case ZYDIS_MNEMONIC_CALL:
					Code::Instructions::Call instr(getOperand(0, instruction, runtime_address));
					callback(instr);
					return;
				}

				if (instruction.operand_count == 0) {
					Code::Instructions::Generic instr(instruction.mnemonic);
					callback(instr);
				}
				else if (instruction.operand_count <= 2) {
					Code::Instructions::GenericWithOperands instr(instruction.mnemonic, instruction.operand_count);
					for (int i = 0; i < instruction.operand_count; i++) {
						instr.setOperand(i, getOperand(i, instruction, runtime_address));
					}
					callback(instr);
				}
			}

			Code::Operand getOperand(int idx, const ZydisDecodedInstruction& instruction, ZyanU64 runtime_address)
			{
				auto& operand = instruction.operands[idx];

				if (operand.reg.value != ZYDIS_REGISTER_NONE) {
					return Code::Operand(operand.reg.value);
				}
				else if(operand.mem.base != ZYDIS_REGISTER_NONE) {
					if (operand.mem.base == ZYDIS_REGISTER_RIP) {
						return Code::Operand(runtime_address + operand.mem.disp.value);
					}
					return Code::Operand(operand.mem.base, operand.mem.disp.value);
				}
				else {
					if (operand.imm.is_relative) {
						return Code::Operand(runtime_address + operand.imm.value.u);
					}
				}

				return Code::Operand(0);
			}
		};
	};
};