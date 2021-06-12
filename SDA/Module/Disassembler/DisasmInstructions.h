#pragma once
#include "DisasmOperand.h"

namespace CE::Disassembler::Code
{
	class Instruction
	{
	public:
		virtual ZydisMnemonic_ getMnemonicId() = 0;

		virtual bool isGeneric();

		virtual bool isJumping();

		virtual bool isBasicManipulating();
	};

	namespace Instructions
	{
		template<int operandCount>
		class AbstractInstructionWithOperands : virtual public Instruction
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

		class JumpInstruction : public AbstractInstructionWithOperands<1>
		{
		public:
			JumpInstruction(Operand location);

			bool isJumping() override;

			bool hasAbsoluteAddr();

			void* getAbsoluteAddr();
		};

		class Call : public JumpInstruction
		{
		public:
			Call(Operand location);

			ZydisMnemonic_ getMnemonicId() override;
		};

		class Jmp : public JumpInstruction
		{
		public:
			Jmp(Operand location);

			ZydisMnemonic_ getMnemonicId() override;
		};

		class BasicManipulation : public AbstractInstructionWithOperands<2>
		{
		public:
			BasicManipulation(Operand op1, Operand op2);

			bool isBasicManipulating() override;
		};

		class Mov : public BasicManipulation
		{
		public:
			Mov(Operand op1, Operand op2);

			ZydisMnemonic_ getMnemonicId() override;
		};

		class Add : public BasicManipulation
		{
		public:
			Add(Operand op1, Operand op2);

			ZydisMnemonic_ getMnemonicId() override;
		};

		class Sub : public BasicManipulation
		{
		public:
			Sub(Operand op1, Operand op2);

			ZydisMnemonic_ getMnemonicId() override;
		};

		class Helper : virtual public Instruction
		{
		public:
			Helper(ZydisMnemonic_ mnemonicId);

			ZydisMnemonic_ getMnemonicId() override;

			bool isGeneric() override;

			virtual void* getAbsoluteAddr();

			virtual int getOperandCount();
		private:
			ZydisMnemonic_ m_mnemonicId;
		};

		class GenericWithOperands : public Helper, public AbstractInstructionWithOperands<2>
		{
		public:
			GenericWithOperands(ZydisMnemonic_ mnemonicId, int operandCount);

			void* getAbsoluteAddr() override;

			int getOperandCount() override;
		private:
			int m_operandCount;
		};
	};
};