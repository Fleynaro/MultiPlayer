#pragma once
#include <main.h>
#include <inttypes.h>
#include "DecMask.h"

namespace CE::Decompiler::PCode
{
	class Register
	{
	public:
		int m_genericId;
		bool m_isVector = false;
		uint64_t m_valueRangeMask;

		Register(int genericId = 0, uint64_t valueRangeMask = 0x0, bool isVector = false)
			: m_genericId(genericId), m_valueRangeMask(valueRangeMask), m_isVector(isVector)
		{}

		int getGenericId() const {
			return m_genericId;
		} 

		int getSize() const {
			return GetBitCountOfMask(m_valueRangeMask) / (m_isVector ? 1 : 8);
		}
	};

	class Varnode
	{
	public:
		virtual ~Varnode() {}

		virtual int getSize() = 0;
	};

	class RegisterVarnode : public Varnode
	{
	public:
		Register m_register;

		RegisterVarnode(Register reg)
			: m_register(reg)
		{}

		int getSize() override {
			return m_register.getSize();
		}
	};

	class ConstantVarnode : public Varnode
	{
	public:
		uint64_t m_value;
		int m_size;

		ConstantVarnode(uint64_t value, int size)
			: m_value(value), m_size(size)
		{}

		int getSize() override {
			return m_size;
		}
	};

	class SymbolVarnode : public Varnode
	{
	public:
		int m_size;

		SymbolVarnode(int size)
			: m_size(size)
		{}

		int getSize() override {
			return m_size;
		}
	};

	class Instruction
	{
	public:
		enum Id {
			NONE,
			//Data Moving
			COPY,
			LOAD,
			STORE,
			//Arithmetic
			INT_ADD,
			INT_SUB,
			INT_CARRY,
			INT_SCARRY,
			INT_SBORROW,
			INT_2COMP,
			INT_MULT,
			INT_DIV,
			INT_SDIV,
			INT_REM,
			INT_SREM,
			//Logical
			INT_NEGATE,
			INT_XOR,
			INT_AND,
			INT_OR,
			INT_LEFT,
			INT_RIGHT,
			INT_SRIGHT,
			//Integer Comparison
			INT_EQUAL,
			INT_NOTEQUAL,
			INT_SLESS,
			INT_SLESSEQUAL,
			INT_LESS,
			INT_LESSEQUAL,
			//Boolean
			BOOL_NEGATE,
			BOOL_XOR,
			BOOL_AND,
			BOOL_OR,
			//Floating Point
			FLOAT_ADD,
			FLOAT_SUB,
			FLOAT_MULT,
			FLOAT_DIV,
			FLOAT_NEG,
			FLOAT_ABS,
			FLOAT_SQRT,
			FLOAT_NAN,
			//Floating Point Compare
			FLOAT_EQUAL,
			FLOAT_NOTEQUAL,
			FLOAT_LESS,
			FLOAT_LESSEQUAL,
			//Floating Point Conversion
			INT2FLOAT,
			FLOAT2FLOAT,
			TRUNC,
			CEIL,
			FLOOR,
			ROUND,
			//Branching
			BRANCH,
			CBRANCH,
			BRANCHIND,
			CALL,
			CALLIND,
			RETURN,
			//Extension / Truncation
			INT_ZEXT,
			INT_SEXT,
			PIECE,
			SUBPIECE,
			//Managed Code
			CPOOLREF,
			NEW
		};

		Id m_id;
		Varnode* m_input0;
		Varnode* m_input1;
		Varnode* m_output;
		
		Instruction(Id id, Varnode* input0, Varnode* input1, Varnode* output, int offset, int orderId)
			: m_id(id), m_input0(input0), m_input1(input1), m_output(output), m_offset(offset), m_orderId(orderId)
		{}

		static bool IsBranching(Id id) {
			return id >= BRANCH && id <= RETURN;
		}

		int getOriginalInstructionOffset() {
			return m_offset;
		}

		int64_t getOffset() {
			return (m_offset << 8) | m_orderId;
		}
	private:
		int m_offset;
		int m_orderId;
	};
};