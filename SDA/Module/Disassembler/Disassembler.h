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
					Pointer,
					AbsAddress
				};

				Operand() = default;

				Operand(ZydisRegister reg)
					: m_register(reg)
				{
					m_type = Register;
				}

				Operand(ZydisRegister reg_base, uint64_t offset)
					: m_register(reg_base), m_offset(offset)
				{
					m_type = Pointer;
				}

				Operand(uint64_t base, int offset)
					: m_offset(base + offset)
				{
					m_type = Pointer;
				}

				Operand(uint64_t value, bool isAddr = false)
					: m_offset(value)
				{
					if (isAddr)
						m_type = AbsAddress;
					else m_type = Constant;
				}

				Type getType() {
					return m_type;
				}

				bool isCalculatedAddress() {
					return getType() == AbsAddress || (getType() == Pointer && getRegister() == ZYDIS_REGISTER_NONE);
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

				virtual bool isJumping() {
					return false;
				}

				virtual bool isBasicManipulating() {
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

				class JumpInstruction : public Instruction, public AbstractInstructionWithOperands<1>
				{
				public:
					JumpInstruction(Operand location)
					{
						setOperand(0, location);
					}

					bool isJumping() override {
						return true;
					}

					bool hasAbsoluteAddr() {
						return getOperand(0).isCalculatedAddress();
					}

					void* getAbsoluteAddr() {
						return getOperand(0).getLocationAddress();
					}
				};

				class Call : public JumpInstruction
				{
				public:
					Call(Operand location)
						: JumpInstruction(location)
					{}

					ZydisMnemonic_ getMnemonicId() override {
						return ZYDIS_MNEMONIC_CALL;
					}
				};

				class Jmp : public JumpInstruction
				{
				public:
					Jmp(Operand location)
						: JumpInstruction(location)
					{}

					ZydisMnemonic_ getMnemonicId() override {
						return ZYDIS_MNEMONIC_JMP;
					}
				};

				class BasicManipulation : public Instruction, public AbstractInstructionWithOperands<2>
				{
				public:
					BasicManipulation(Operand op1, Operand op2)
					{
						setOperand(0, op1);
						setOperand(1, op2);
					}

					bool isBasicManipulating() override {
						return true;
					}
				};

				class Mov : public BasicManipulation
				{
				public:
					Mov(Operand op1, Operand op2)
						: BasicManipulation(op1, op2)
					{}

					ZydisMnemonic_ getMnemonicId() override {
						return ZYDIS_MNEMONIC_MOV;
					}
				};

				class Add : public BasicManipulation
				{
				public:
					Add(Operand op1, Operand op2)
						: BasicManipulation(op1, op2)
					{}

					ZydisMnemonic_ getMnemonicId() override {
						return ZYDIS_MNEMONIC_ADD;
					}
				};

				class Sub : public BasicManipulation
				{
				public:
					Sub(Operand op1, Operand op2)
						: BasicManipulation(op1, op2)
					{}

					ZydisMnemonic_ getMnemonicId() override {
						return ZYDIS_MNEMONIC_SUB;
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

					virtual int getOperandCount() {
						return 0;
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
							if (getOperand(i).isCalculatedAddress()) {
								return getOperand(i).getLocationAddress();
							}
						}
						return nullptr;
					}

					int getOperandCount() override {
						return m_operandCount;
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

			int getSize() {
				return m_size;
			}

			ZyanU64 getCurrentAddress() {
				return m_runtime_address;
			}

			ZyanU8 getCurrentLength() {
				return m_instr_length;
			}
		private:
			void* m_startAddr;
			int m_size;
			ZyanU64 m_runtime_address;
			ZyanU8 m_instr_length;

			void doCallback(const ZydisDecodedInstruction& instruction, const std::function<bool(Code::Instruction&)>& callback)
			{
				switch(instruction.mnemonic)
				{
				case ZYDIS_MNEMONIC_CALL: {
					Code::Instructions::Call instr(getOperand(0, instruction));
					callback(instr);
					return;
				}
				case ZYDIS_MNEMONIC_JMP: {
					Code::Instructions::Jmp instr(getOperand(0, instruction));
					callback(instr);
					return;
				}

				case ZYDIS_MNEMONIC_MOV: {
					Code::Instructions::Mov instr(getOperand(0, instruction), getOperand(1, instruction));
					callback(instr);
					return;
				}
				case ZYDIS_MNEMONIC_ADD: {
					Code::Instructions::Add instr(getOperand(0, instruction), getOperand(1, instruction));
					callback(instr);
					return;
				}
				case ZYDIS_MNEMONIC_SUB: {
					Code::Instructions::Sub instr(getOperand(0, instruction), getOperand(1, instruction));
					callback(instr);
					return;
				}
				}

				if (instruction.operand_count == 0) {
					Code::Instructions::Generic instr(instruction.mnemonic);
					callback(instr);
				}
				else if (instruction.operand_count <= 2) {
					Code::Instructions::GenericWithOperands instr(instruction.mnemonic, instruction.operand_count);
					for (int i = 0; i < instruction.operand_count; i++) {
						instr.setOperand(i, getOperand(i, instruction));
					}
					callback(instr);
				}
			}

			Code::Operand getOperand(int idx, const ZydisDecodedInstruction& instruction)
			{
				auto& operand = instruction.operands[idx];

				if (operand.reg.value != ZYDIS_REGISTER_NONE) {
					return Code::Operand(operand.reg.value);
				}
				else if(operand.mem.base != ZYDIS_REGISTER_NONE) {
					if (operand.mem.base == ZYDIS_REGISTER_RIP) {
						return Code::Operand(getCurrentAddress() + getCurrentLength(), (int)operand.mem.disp.value);
					}
					return Code::Operand(operand.mem.base, operand.mem.disp.value);
				}
				else {
					if (operand.imm.is_relative) {
						return Code::Operand(getCurrentAddress() + getCurrentLength() + operand.imm.value.u, true);
					}
				}

				return Code::Operand(0);
			}
		};
	};
};