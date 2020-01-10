#pragma once

#include "main.h"
#include <inttypes.h>


#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>


/*
	TODO:
	1) Константы не только в mov, но и в остальных выражениях
	2) Условные выражения свои
	3) 
*/


namespace CE
{
	namespace Disassembler
	{
		static ZydisDecoder decoder;
		static ZydisFormatter formatter;

		static void init() {
			ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
			ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		}
	};

	namespace Assembly
	{
		class ByteStream
		{
		public:
			ByteStream(byte* addr = nullptr)
				: m_bytes(addr)
			{}

			void writeByte(byte value)
			{
				write(value);
			}

			template<typename T>
			void write(T value)
			{
				if(m_writeFlag)
					(T&)m_bytes[m_offset] = value;
				m_offset += sizeof(T);
			}

			void writeBytes(const std::vector<byte>& bytes)
			{
				for (auto const& byte : bytes) {
					writeByte(byte);
				}
			}

			byte* getBytes() {
				return m_bytes;
			}

			byte* getCurrentLocation() {
				return &m_bytes[m_offset];
			}

			int getOffset() {
				return m_offset;
			}

			void setWriteFlag(bool flag) {
				m_writeFlag = flag;
				m_offset = 0;
			}

			void setAddr(byte* addr) {
				m_bytes = addr;
			}

			void debugShow() {
				using namespace CE::Disassembler;
				printf("=== Assembler code ===\n");

				ZyanU64 runtime_address = (ZyanU64)m_bytes;
				ZyanUSize offset = 0;

				ZydisFormatter formatter;
				ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
				ZydisDecoder decoder;
				ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

				ZydisDecodedInstruction instruction;
				while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)((ZyanU64)m_bytes + offset), m_offset - offset,
					&instruction)))
				{
					printf("%016" PRIX64 "  ", runtime_address);

					char buffer[256];
					ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer),
						runtime_address);
					puts(buffer);

					offset += instruction.length;
					runtime_address += instruction.length;
				}
				printf("\n\n");
			}
		private:
			byte* m_bytes;
			int m_offset = 0;
			bool m_writeFlag = true;
		};

		class Operand
		{
		public:
			virtual bool isConstant() = 0;
			virtual bool isRegister() = 0;
			virtual bool isPointer() = 0;
			virtual bool isLabel() = 0;

			void setExternal() {
				m_external = true;
			}

			bool isExternal() {
				return m_external;
			}
		private:
			bool m_external = false;
		};

		class Constant : public Operand
		{
		public:
			Constant(uint64_t value)
				: m_value(value)
			{}

			bool isConstant() {
				return true;
			}

			bool isRegister() {
				return false;
			}

			bool isPointer() {
				return false;
			}

			bool isLabel() {
				return false;
			}

			uint64_t getValue() {
				return m_value;
			}

			void setValue(uint64_t value) {
				m_value = value;
			}
		private:
			uint64_t m_value;
		};

		class Label : public Operand
		{
		public:
			Label(void* addr = nullptr, bool external = true)
				: m_addr(addr)
			{
				if(external)
					setExternal();
			}

			void* getAddr() {
				return m_addr;
			}

			void setAddr(void* addr) {
				m_addr  = addr;
			}

			DWORD getCalculatedJmpFrom(void* from) {
				return (std::uintptr_t)getAddr() - (std::uintptr_t)from;
			}

			bool isConstant() {
				return false;
			}

			bool isRegister() {
				return false;
			}

			bool isPointer() {
				return false;
			}

			bool isLabel() {
				return true;
			}
		private:
			void* m_addr;
		};

		class Register : public Operand
		{
		public:
			enum RegisterLength
			{
				rl_8 = 1,
				rl_16,
				rl_32,
				rl_64,
				rl_128,
				rl_256
			};
			enum Register64
			{
				//8 bit
				al = 0x10,
				cl,
				dl,
				bl,
				spl,
				bpl,
				sil,
				dil,
				r8b,
				r9b,
				r10b,
				r11b,
				r12b,
				r13b,
				r14b,
				r15b,

				//16 bit
				ax = 0x20,
				cx,
				dx,
				bx,
				sp,
				bp,
				si,
				di,
				r8w,
				r9w,
				r10w,
				r11w,
				r12w,
				r13w,
				r14w,
				r15w,

				//32 bit
				eax = 0x30,
				ecx,
				edx,
				ebx,
				esp,
				ebp,
				esi,
				edi,
				r8d,
				r9d,
				r10d,
				r11d,
				r12d,
				r13d,
				r14d,
				r15d,

				//64 bit
				rax = 0x40,
				rcx,
				rdx,
				rbx,
				rsp,
				rbp,
				rsi,
				rdi,
				r8,
				r9,
				r10,
				r11,
				r12,
				r13,
				r14,
				r15,

				//128 bit
				xmm0 = 0x50,
				xmm1,
				xmm2,
				xmm3,
				xmm4,
				xmm5,
				xmm6,
				xmm7,
				xmm8,
				xmm9,
				xmm10,
				xmm11,
				xmm12,
				xmm13,
				xmm14,
				xmm15,

				//256 bit
				ymm0 = 0x60,
				ymm1,
				ymm2,
				ymm3,
				ymm4,
				ymm5,
				ymm6,
				ymm7,
				ymm8,
				ymm9,
				ymm10,
				ymm11,
				ymm12,
				ymm13,
				ymm14,
				ymm15
			};

			Register(Register64 reg)
				: m_reg(reg)
			{}

			bool isGeneric() {
				if (getRegister() >> 3 & 0b1) {
					return false;
				}
				return true;
			}

			bool isUser() {
				return !isGeneric();
			}

			bool isConstant() {
				return false;
			}

			bool isRegister() {
				return true;
			}

			bool isPointer() {
				return false;
			}

			bool isLabel() {
				return false;
			}

			int getIndex() {
				return (int)getRegister() & 0b111;
			}

			int getFullIndex() {
				return (int)getRegister() & 0b1111;
			}

			RegisterLength getLength() {
				return (RegisterLength)((int)getRegister() >> 4 & 0xF);
			}

			Register64 getRegister() {
				return m_reg;
			}
		private:
			Register64 m_reg;
		};

		class Pointer : public Operand
		{
		public:
			enum Length
			{
				byte,
				word,
				dword,
				qword
			};

			Pointer(Operand* op1, Operand* op2 = nullptr, Length len = qword)
				: m_base(op1), m_offset(op2), m_len(len)
			{}

			~Pointer() {
				if(!m_base->isExternal())
					delete m_base;

				if (m_offset != nullptr) {
					if(!m_offset->isExternal())
						delete m_offset;
				}
			}

			bool isConstant() {
				return false;
			}

			bool isRegister() {
				return false;
			}

			bool isPointer() {
				return true;
			}

			bool isLabel() {
				return false;
			}

			bool hasOffset() {
				return m_offset != nullptr;
			}

			Operand& getBase() {
				return *m_base;
			}

			Operand& getOffset() {
				return *m_offset;
			}

			Length getLength() {
				return m_len;
			}
		private:
			Length m_len;
			Operand* m_base;
			Operand* m_offset;
		};

		class Block;
		class Unit
		{
		public:
			virtual void compile(ByteStream& st) = 0;
			virtual ~Unit() {}

			enum class Type
			{
				Instruction,
				Label,
				RawBlock,
				Block
			};
			virtual Type getType() = 0;

			void setParent(Block* parent) {
				m_parent = parent;
			}

			Block* getParent() {
				return m_parent;
			}
		private:
			Block* m_parent = nullptr;
		};

		namespace Instruction
		{
			class Instruction : public Unit
			{
			public:
				Type getType() override {
					return Type::Instruction;
				}
			};

			class OperandZero
			{
			public:
				OperandZero() = default;
			};

			class OperandOne
			{
			public:
				OperandOne(Operand* op)
					: m_op(op)
				{}
				virtual ~OperandOne() {
					if(!m_op->isExternal())
						delete m_op;
				}

				Operand& getOperand() {
					return *m_op;
				}
			private:
				Operand* m_op;
			};

			class OperandTwo
			{
			public:
				OperandTwo(Operand* op1, Operand* op2)
					: m_op1(op1), m_op2(op2)
				{}

				virtual ~OperandTwo() {
					if(!m_op1->isExternal())
						delete m_op1;
					if(!m_op2->isExternal())
						delete m_op2;
				}

				Operand& getFirstOperand() {
					return *m_op1;
				}

				Operand& getSecondOperand() {
					return *m_op2;
				}

				Operand* getFirstOperandPtr() {
					return m_op1;
				}

				Operand* getSecondOperandPtr() {
					return m_op2;
				}

				template<typename T>
				void write_operands2(ByteStream& st, Register& reg1, Register& reg2, T cmd_id)
				{
					byte mask_user_reg = reg1.isUser() | reg2.isUser() << 2;

					switch (reg2.getLength())
					{
					case Register::rl_8:
						//MOV AL, AL
						if (mask_user_reg) st.writeByte(byte(0x40 + mask_user_reg));
						st.write<T>(cmd_id - 1);
						break;
					case Register::rl_16:
						//MOV AX, AX
						st.writeByte(0x66);
						if (mask_user_reg) st.writeByte(byte(0x40 + mask_user_reg));
						st.write(cmd_id);
						break;
					case Register::rl_128:
					case Register::rl_32:
						//MOV EAX, EAX
						if (mask_user_reg) st.writeByte(byte(0x40 + mask_user_reg));
						st.write(cmd_id);
						break;
					case Register::rl_64:
						//MOV RAX, RAX
						st.writeByte(byte(0x40 + mask_user_reg + 0x8));
						st.write(cmd_id);
						break;
					}
				}

				template<typename T = byte>
				void compile_command(ByteStream& st, T cmd_id, int symmetry = 2)
				{
					if (getFirstOperand().isRegister() && getSecondOperand().isRegister())
					{
						Register& reg1 = (Register&)getFirstOperand();
						Register& reg2 = (Register&)getSecondOperand();

						write_operands2(st, reg1, reg2, cmd_id);
						st.writeByte(0xC0 + 0x8 * reg2.getIndex() + reg1.getIndex());
						return;
					}

					if (getFirstOperand().isRegister() && getSecondOperand().isPointer()
						|| getFirstOperand().isPointer() && getSecondOperand().isRegister())
					{
						Register* reg;
						Pointer* ptr;

						if (getFirstOperand().isRegister() && getSecondOperand().isPointer()) {
							cmd_id += symmetry;

							reg = (Register*)getFirstOperandPtr();
							ptr = (Pointer*)getSecondOperandPtr();
						}
						else {
							ptr = (Pointer*)getFirstOperandPtr();
							reg = (Register*)getSecondOperandPtr();
						}

						if (ptr->getBase().isRegister() && ptr->getOffset().isConstant())
						{
							Register& base_reg = (Register&)ptr->getBase();
							Constant& offset_const = (Constant&)ptr->getOffset();
							
							if (base_reg.getLength() == Register::rl_64)
							{
								write_operands2(st, base_reg, *reg, cmd_id);
								if (base_reg.getFullIndex() == 4) {
									//rsp, esp, ...
									st.writeByte(0x44 + 0x8 * reg->getIndex());
									st.writeByte(0x24);
								}
								else {
									st.writeByte(0x40 + 0x8 * reg->getIndex() + base_reg.getIndex());
								}
								st.writeByte(offset_const.getValue());
							}
						}
						else if (ptr->getBase().isConstant() && (!ptr->hasOffset() || ptr->getOffset().isConstant()))
						{
							Constant& base_const = (Constant&)ptr->getBase();
							if (ptr->hasOffset()) {
								Constant& offset_const = (Constant&)ptr->getOffset();
								base_const.setValue(base_const.getValue() + offset_const.getValue());
							}

							if (getFirstOperand().isRegister() && getSecondOperand().isPointer())
								cmd_id = 0xA1; else cmd_id = 0xA3;

							if (reg->getLength() == Register::rl_64)
								st.writeByte(0x48);
							else if (reg->getLength() == Register::rl_16)
								st.writeByte(0x66);
							else if (reg->getLength() == Register::rl_8)
								cmd_id--;
							st.writeByte(cmd_id);
							st.write<uint64_t>(base_const.getValue());
						}
						return;
					}
				}

				void compile_reg_const(ByteStream& st, BYTE cmd_base, BYTE rax_base)
				{
					Register& reg = (Register&)getFirstOperand();
					uint64_t value = ((Constant&)getSecondOperand()).getValue();

					switch (reg.getLength())
					{
					case Register::rl_8:
						if (reg.isUser())
							st.writeByte(0x41);
						if (reg.getFullIndex() != 0) {
							st.writeByte(0x80);
							st.writeByte(cmd_base + reg.getIndex());
						}
						else {
							st.writeByte(rax_base - 1);
						}
						st.write<BYTE>(value);
						break;
					case Register::rl_16:
						st.writeByte(0x66);
						if (reg.isUser())
							st.writeByte(0x41);
						st.writeByte(0x83);
						st.writeByte(cmd_base + reg.getIndex());
						st.write<BYTE>(value);
						break;
					case Register::rl_32:
						if (reg.isUser())
							st.writeByte(0x41);
						if (value <= 127) {
							st.writeByte(0x83);
							st.writeByte(cmd_base + reg.getIndex());
							st.write<BYTE>(value);
						}
						else {
							if (reg.getFullIndex() != 0) {
								st.writeByte(0x81);
								st.writeByte(cmd_base + reg.getIndex());
							}
							else {
								st.writeByte(rax_base);
							}
							st.write<DWORD>(value);
						}
						break;
					case Register::rl_64:
						if (reg.isUser())
							st.writeByte(0x49);
						else
							st.writeByte(0x48);

						if (value <= 127) {
							st.writeByte(0x83);
							st.writeByte(cmd_base + reg.getIndex());
							st.write<BYTE>(value);
						}
						else {
							if (reg.getFullIndex() != 0) {
								st.writeByte(0x81);
								st.writeByte(cmd_base + reg.getIndex());
							}
							else {
								st.writeByte(rax_base);
							}
							st.write<DWORD>(value);
						}
						break;
					}
				}
			private:
				Operand* m_op1;
				Operand* m_op2;
			};

			class Nop
				: public Instruction, public OperandZero
			{
			public:
				void compile(ByteStream& st) override
				{
					st.writeByte(0x90);
				}
			};

			class Ret
				: public Instruction, public OperandZero
			{
			public:
				void compile(ByteStream& st) override
				{
					st.writeByte(0xC3);
				}
			};

			class Push
				: public Instruction, public OperandOne
			{
			public:
				Push(Operand* op)
					: OperandOne(op)
				{}

				void compile(ByteStream& st) override
				{
					if (getOperand().isRegister()) {
						Register& reg = (Register&)getOperand();

						if (reg.isGeneric()) {
							st.writeByte(0x50 + reg.getIndex());
						}
						else {
							st.writeByte(0x41);
							st.writeByte(0x50 + reg.getIndex());
						}
					}
				}
			};

			class Pop
				: public Instruction, public OperandOne
			{
			public:
				Pop(Operand* op)
					: OperandOne(op)
				{}

				void compile(ByteStream& st) override
				{
					if (getOperand().isRegister()) {
						Register& reg = (Register&)getOperand();

						if (reg.isGeneric()) {
							st.writeByte(0x58 + reg.getIndex());
						}
						else {
							st.writeByte(0x41);
							st.writeByte(0x58 + reg.getIndex());
						}
					}
				}
			};

			class Jmp
				: public Instruction, public OperandOne
			{
			public:
				Jmp(Operand* op)
					: OperandOne(op)
				{}

				template<typename T>
				void compile_command(ByteStream& st, T cmd_id_long, byte cmd_id_short = 0xFF)
				{
					DWORD delta = 0;
					if (getOperand().isConstant()) {
						Constant& c = (Constant&)getOperand();
						delta = c.getValue();
					}
					else if (getOperand().isLabel()) {
						Label& label = (Label&)getOperand();
						delta = label.getCalculatedJmpFrom(st.getCurrentLocation());
					}

					if (delta < 0xFF && cmd_id_short != 0xFF && false) {
						st.writeByte(cmd_id_short);
						st.writeByte(delta);
					}
					else {
						st.write(cmd_id_long);
						st.write<DWORD>(delta - (sizeof(T) + 4));
					}
				}

				void compile(ByteStream& st) override
				{
					if (getOperand().isRegister()) {
						Register& reg = (Register&)getOperand();
						if (reg.isUser()) {
							st.writeByte(0x41);
						}
						st.writeByte(0xFF);
						st.writeByte(0xE0 + reg.getIndex());
						return;
					}
					compile_command(st, (BYTE)0xE9, 0xEB);
				}
			};

			class Jz
				: public Jmp
			{
			public:
				Jz(Operand* op)
					: Jmp(op)
				{}

				void compile(ByteStream& st) override
				{
					compile_command(st, (WORD)0x840F, 0x74);
				}
			};

			class Jnz
				: public Jmp
			{
			public:
				Jnz(Operand* op)
					: Jmp(op)
				{}

				void compile(ByteStream& st) override
				{
					compile_command(st, (WORD)0x850F, 0x75);
				}
			};

			class Call
				: public Jmp
			{
			public:
				Call(Operand* op)
					: Jmp(op)
				{}

				void compile(ByteStream& st) override
				{
					if (getOperand().isRegister()) {
						Register& reg = (Register&)getOperand();
						if (reg.isUser()) {
							st.writeByte(0x41);
						}
						st.writeByte(0xFF);
						st.writeByte(0xD0 + reg.getIndex());
						return;
					}
					compile_command(st, (BYTE)0xE8);
				}
			};

			class Add
				: public Instruction, public OperandTwo
			{
			public:
				Add(Operand* op1, Operand* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					if (getFirstOperand().isRegister() && getSecondOperand().isConstant())
					{
						compile_reg_const(st, 0xC0, 0x05);
						return;
					}
					compile_command(st, (BYTE)0x01);
				}
			};

			class Sub
				: public Instruction, public OperandTwo
			{
			public:
				Sub(Operand* op1, Operand* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					if (getFirstOperand().isRegister() && getSecondOperand().isConstant())
					{
						compile_reg_const(st, 0xE8, 0x2D);
						return;
					}
					compile_command(st, (BYTE)0x29);
				}
			};

			class Or
				: public Instruction, public OperandTwo
			{
			public:
				Or(Operand* op1, Operand* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					if (getFirstOperand().isRegister() && getSecondOperand().isConstant())
					{
						compile_reg_const(st, 0xC8, 0x0D);
						return;
					}
					compile_command(st, (BYTE)0x09);
				}
			};

			class And
				: public Instruction, public OperandTwo
			{
			public:
				And(Operand* op1, Operand* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					if (getFirstOperand().isRegister() && getSecondOperand().isConstant())
					{
						compile_reg_const(st, 0xE0, 0x25);
						return;
					}
					compile_command(st, (BYTE)0x21);
				}
			};

			class Test
				: public Instruction, public OperandTwo
			{
			public:
				Test(Operand* op1, Operand* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					compile_command(st, (BYTE)0x85, 0);
				}
			};

			class Cmp
				: public Instruction, public OperandTwo
			{
			public:
				Cmp(Operand* op1, Operand* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					if (getFirstOperand().isRegister() && getSecondOperand().isConstant())
					{
						compile_reg_const(st, 0xF8, 0x3D);
						return;
					}
					compile_command(st, (BYTE)0x39);
				}
			};

			class Lea
				: public Instruction, public OperandTwo
			{
			public:
				Lea(Operand* op1, Pointer* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					compile_command(st, (BYTE)0x8B);
				}
			};
			
			class Mov
				: public Instruction, public OperandTwo
			{
			public:
				Mov(Operand* op1, Operand* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					if (getFirstOperand().isRegister() && (getSecondOperand().isConstant() || getSecondOperand().isLabel()))
					{
						Register& reg = (Register&)getFirstOperand();

						uint64_t value = 0;
						if (getSecondOperand().isConstant()) {
							value = ((Constant&)getSecondOperand()).getValue();
						}
						else {
							value = (uint64_t)((Label&)getSecondOperand()).getAddr();
						}
						
						switch (reg.getLength())
						{
						case Register::rl_8:
							if (reg.isUser())
								st.writeByte(0x41);
							st.writeByte(0xB0 + reg.getIndex());
							st.write<BYTE>(value);
							break;
						case Register::rl_16:
							st.writeByte(0x66);
							if (reg.isUser())
								st.writeByte(0x41);
							st.writeByte(0xB8 + reg.getIndex());
							st.write<WORD>(value);
							break;
						case Register::rl_32:
							if (reg.isUser())
								st.writeByte(0x41);
							st.writeByte(0xB8 + reg.getIndex());
							st.write<DWORD>(value);
							break;
						case Register::rl_64:
							if (reg.isUser())
								st.writeByte(0x49);
							else
								st.writeByte(0x48);

							if (value <= 0xFFFFFFFF && !getSecondOperand().isLabel()) {
								st.writeByte(0xC7);
								st.writeByte(0xC0 + reg.getIndex());
								st.write<DWORD>(value);
							}
							else {
								st.writeByte(0xB8 + reg.getIndex());
								st.write(value);
							}
							break;
						}		
						return;
					}

					compile_command(st, (BYTE)0x89);
				}
			};

			class Movss
				: public Instruction, public OperandTwo
			{
			public:
				Movss(Operand* op1, Operand* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					st.writeByte(0xF3);
					compile_command(st, (WORD)0x110F, -0x100);
				}
			};

			class Movsd
				: public Instruction, public OperandTwo
			{
			public:
				Movsd(Operand* op1, Operand* op2)
					: OperandTwo(op1, op2)
				{}

				void compile(ByteStream& st) override
				{
					st.writeByte(0xF2);
					compile_command(st, (WORD)0x110F, -0x100);
				}
			};
		};

		class AutoLabel : public Unit
		{
		public:
			AutoLabel(Label* label)
				: m_label(label)
			{}

			Type getType() override {
				return Type::Label;
			}

			void compile(ByteStream& st) override
			{
				m_label->setAddr(st.getCurrentLocation());
			}
		private:
			Label* m_label;
		};

		class RawBlock : public Unit
		{
		public:
			RawBlock(byte* addr = nullptr, int size = 0)
				: m_bytes(addr), m_size(size)
			{}

			Type getType() override {
				return Type::RawBlock;
			}

			void setData(byte* addr, int size)
			{
				m_bytes = addr;
				m_size = size;
			}

			void compile(ByteStream& st) override
			{
				for (int i = 0; i < m_size; i++) {
					st.writeByte(m_bytes[i]);
				}
			}
		private:
			byte* m_bytes;
			int m_size;
		};

		class Block : public Unit
		{
		public:
			Block(uint64_t userId = 0)
				: m_userId(userId)
			{}
			virtual ~Block() {
				for (auto unit : m_units) {
					if (unit->getType() != Type::Block) {
						delete unit;
					}
				}
			}

			Type getType() override {
				return Type::Block;
			}

			Block& label(Label& label) {
				addUnit(new AutoLabel(&label));
				return *this;
			}

			Block& beginBlock() {
				Block* block = new Block;
				addUnit(block);
				return *block;
			}

			Block& endBlock() {
				return *getParent();
			}

			Block& rawBlock(RawBlock** rawBlockPtr = nullptr) {
				RawBlock* rawBlock = new RawBlock;
				addUnit(rawBlock);
				if (rawBlockPtr != nullptr) {
					*rawBlockPtr = rawBlock;
				}
				return *this;
			}

			Block& nop() {
				addUnit(new Instruction::Nop);
				return *this;
			}

			Block& ret() {
				addUnit(new Instruction::Ret);
				return *this;
			}

			Block& push(Register::Register64 reg) {
				addUnit(new Instruction::Push(new Register(reg)));
				return *this;
			}

			Block& pop(Register::Register64 reg) {
				addUnit(new Instruction::Pop(new Register(reg)));
				return *this;
			}

			Block& call(Label* label) {
				addUnit(new Instruction::Call(label));
				return *this;
			}

			Block& call(void* addr) {
				return call(new Label(addr));
			}

			Block& call(Register::Register64 reg) {
				addUnit(new Instruction::Call(new Register(reg)));
				return *this;
			}

			Block& jmp(Label* label) {
				addUnit(new Instruction::Jmp(label));
				return *this;
			}

			Block& jmp(void* addr) {
				return jmp(new Label(addr, false));
			}

			Block& jmp(Register::Register64 reg) {
				addUnit(new Instruction::Jmp(new Register(reg)));
				return *this;
			}

			Block& jz(Label* label) {
				addUnit(new Instruction::Jz(label));
				return *this;
			}

			Block& jz(void* addr) {
				return jz(new Label(addr));
			}

			Block& jnz(Label* label) {
				addUnit(new Instruction::Jnz(label));
				return *this;
			}

			Block& jnz(void* addr) {
				return jnz(new Label(addr));
			}

			Block& test(Operand* op1, Operand* op2) {
				addUnit(new Instruction::Test(op1, op2));
				return *this;
			}

			Block& test(Register::Register64 op1, Register::Register64 op2) {
				return test(new Register(op1), new Register(op2));
			}

			Block& cmp(Operand* op1, Operand* op2) {
				addUnit(new Instruction::Cmp(op1, op2));
				return *this;
			}

			Block& cmp(Register::Register64 op1, Register::Register64 op2) {
				return cmp(new Register(op1), new Register(op2));
			}

			Block& cmp(Register::Register64 op1, uint64_t op2) {
				return cmp(new Register(op1), new Constant(op2));
			}

			Block& add(Operand* op1, Operand* op2) {
				addUnit(new Instruction::Add(op1, op2));
				return *this;
			}

			Block& add(Register::Register64 op1, Register::Register64 op2) {
				return add(new Register(op1), new Register(op2));
			}

			Block& add(Register::Register64 op1, uint64_t op2) {
				return add(new Register(op1), new Constant(op2));
			}

			Block& sub(Operand* op1, Operand* op2) {
				addUnit(new Instruction::Sub(op1, op2));
				return *this;
			}

			Block& sub(Register::Register64 op1, Register::Register64 op2) {
				return sub(new Register(op1), new Register(op2));
			}

			Block& sub(Register::Register64 op1, uint64_t op2) {
				return sub(new Register(op1), new Constant(op2));
			}

			Block& Or(Operand* op1, Operand* op2) {
				addUnit(new Instruction::Or(op1, op2));
				return *this;
			}

			Block& Or(Register::Register64 op1, Register::Register64 op2) {
				return Or(new Register(op1), new Register(op2));
			}

			Block& And(Operand* op1, Operand* op2) {
				addUnit(new Instruction::And(op1, op2));
				return *this;
			}

			Block& And(Register::Register64 op1, Register::Register64 op2) {
				return And(new Register(op1), new Register(op2));
			}

			Block& lea(Operand* op1, Pointer* op2) {
				addUnit(new Instruction::Lea(op1, op2));
				return *this;
			}

			Block& lea(Register::Register64 op1, Register::Register64 op2, int offset) {
				return lea(new Register(op1), new Pointer(new Register(op2), new Constant(offset)));
			}

			Block& mov(Operand* op1, Operand* op2) {
				addUnit(new Instruction::Mov(op1, op2));
				return *this;
			}

			Block& mov(Register::Register64 op1, Register::Register64 op2) {
				return mov(new Register(op1), new Register(op2));
			}

			Block& mov(Register::Register64 op1, Register::Register64 op2, int offset) {
				return mov(new Register(op1), new Pointer(new Register(op2), new Constant(offset)));
			}

			Block& mov(Register::Register64 op1, int offset, Register::Register64 op2) {
				return mov(new Pointer(new Register(op1), new Constant(offset)), new Register(op2));
			}

			Block& mov(Register::Register64 op1, uint64_t op2) {
				return mov(new Register(op1), new Constant(op2));
			}

			Block& mov_ptr(Register::Register64 op1, uint64_t op2) {
				return mov(new Register(op1), new Pointer(new Constant(op2)));
			}

			Block& mov_ptr(uint64_t op1, Register::Register64 op2) {
				return mov(new Pointer(new Constant(op1)), new Register(op2));
			}

			Block& mov(Register::Register64 op1, Label* label) {
				return mov(new Register(op1), label);
			}

			Block& movss(Operand* op1, Operand* op2) {
				addUnit(new Instruction::Movss(op1, op2));
				return *this;
			}

			Block& movss(Register::Register64 op1, Register::Register64 op2) {
				return movss(new Register(op1), new Register(op2));
			}

			Block& movss(Register::Register64 op1, Register::Register64 op2, int offset) {
				return movss(new Register(op1), new Pointer(new Register(op2), new Constant(offset)));
			}

			Block& movss(Register::Register64 op1, int offset, Register::Register64 op2) {
				return movss(new Pointer(new Register(op1), new Constant(offset)), new Register(op2));
			}

			Block& movsd(Operand* op1, Operand* op2) {
				addUnit(new Instruction::Movsd(op1, op2));
				return *this;
			}

			Block& movsd(Register::Register64 op1, Register::Register64 op2) {
				return movsd(new Register(op1), new Register(op2));
			}

			Block& movsd(Register::Register64 op1, Register::Register64 op2, int offset) {
				return movsd(new Register(op1), new Pointer(new Register(op2), new Constant(offset)));
			}

			Block& movsd(Register::Register64 op1, int offset, Register::Register64 op2) {
				return movsd(new Pointer(new Register(op1), new Constant(offset)), new Register(op2));
			}

			Block& addUnit(Unit* unit) {
				m_units.push_back(unit);
				unit->setParent(this);
				return *this;
			}

			void compile(ByteStream& st) override
			{
				for (auto unit : m_units) {
					unit->compile(st);
				}
			}
		private:
			uint64_t m_userId;
			std::vector<Unit*> m_units;
		};
	};
};