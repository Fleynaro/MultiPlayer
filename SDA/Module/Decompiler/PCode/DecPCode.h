#pragma once
#include <main.h>
#include <inttypes.h>
#include "../DecMask.h"
#include <magic_enum.hpp>

//for debug x86
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

namespace CE::Decompiler::PCode
{
	using RegisterId = int;

	class Register
	{
	public:
		enum class Type {
			Generic,
			StackPointer,
			InstructionPointer,
			Flag,
			Vector
		};

		RegisterId m_genericId;
		Type m_type;
		ExtBitMask m_valueRangeMask;

		Register(RegisterId genericId = 0, ExtBitMask valueRangeMask = 0x0, Type type = Type::Generic)
			: m_genericId(genericId), m_valueRangeMask(valueRangeMask), m_type(type)
		{}

		RegisterId getGenericId() const {
			return m_genericId;
		}

		bool isValid() const {
			return m_genericId != 0;
		}

		bool isPointer() const {
			return m_type == Type::StackPointer || m_type == Type::InstructionPointer;
		}

		bool isVector() const {
			return m_type == Type::Vector;
		}

		int getSize() const {
			return m_valueRangeMask.getSize();
		}

		bool intersect(const Register& reg) const {
			//if the masks intersected
			return m_genericId == reg.m_genericId && !(m_valueRangeMask & reg.m_valueRangeMask).isZero();
		}

		bool operator ==(const Register& reg) const {
			return m_genericId == reg.m_genericId && m_valueRangeMask == reg.m_valueRangeMask;
		}

		std::string printDebug() {
			auto regId = (ZydisRegister)m_genericId;

			auto size = getSize();
			std::string maskStr = std::to_string(size);
			if (isVector()) {
				if (size == 4 || size == 8) {
					maskStr = std::string(size == 4 ? "D" : "Q") + (char)('a' + (char)(m_valueRangeMask.getOffset() / (size * 8)));
				}
			}

			if (regId != ZYDIS_REGISTER_RFLAGS)
				return std::string(ZydisRegisterGetString(regId)) + ":" + maskStr;

			std::string flagName = "flag";
			auto flag = (ZydisCPUFlag)m_valueRangeMask.getOffset();
			if (flag == ZYDIS_CPUFLAG_CF)
				flagName = "CF";
			else if (flag == ZYDIS_CPUFLAG_OF)
				flagName = "OF";
			else if (flag == ZYDIS_CPUFLAG_SF)
				flagName = "SF";
			else if (flag == ZYDIS_CPUFLAG_ZF)
				flagName = "ZF";
			else if (flag == ZYDIS_CPUFLAG_AF)
				flagName = "AF";
			else if (flag == ZYDIS_CPUFLAG_PF)
				flagName = "PF";
			return flagName + ":1";
		}
	};

	static ExtBitMask GetValueRangeMaskWithException(const PCode::Register& reg) {
		if (reg.m_type == Register::Type::Generic && reg.m_valueRangeMask == ExtBitMask(4))
			return ExtBitMask(8);
		return reg.m_valueRangeMask;
	}

	class Varnode
	{
	public:
		virtual ~Varnode() {}

		virtual int getSize() = 0;

		virtual ExtBitMask getMask() {
			return ExtBitMask(getSize());
		}

		virtual std::string printDebug() = 0;
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

		ExtBitMask getMask() override {
			return m_register.m_valueRangeMask;
		}

		std::string printDebug() override {
			return m_register.printDebug();
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

		std::string printDebug() override {
			return std::to_string((int64_t&)m_value) + ":" + std::to_string(getSize());
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

		std::string printDebug() override {
			return "$U" + std::to_string((uint64_t)this % 10000) + ":" + std::to_string(getSize());
		}
	};

	enum class InstructionId {
		NONE,
		UNKNOWN,
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
		FLOAT2INT,
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

	class Instruction
	{
	public:
		InstructionId m_id;
		Varnode* m_input0;
		Varnode* m_input1;
		Varnode* m_output;
		std::string m_originalView;
		
		Instruction(InstructionId id, Varnode* input0, Varnode* input1, Varnode* output, int originalInstructionOffset, int originalInstructionLength, int orderId)
			: m_id(id), m_input0(input0), m_input1(input1), m_output(output), m_originalInstructionOffset(originalInstructionOffset), m_originalInstructionLength(originalInstructionLength), m_orderId(orderId)
		{}

		static bool IsBranching(InstructionId id) {
			return id >= InstructionId::BRANCH && id <= InstructionId::RETURN;
		}

		int getOriginalInstructionOffset() {
			return m_originalInstructionOffset;
		}

		int getOriginalInstructionLength() {
			return m_originalInstructionLength;
		}

		int getOrderId() {
			return m_orderId;
		}

		int64_t getOffset() {
			return (m_originalInstructionOffset << 8) | m_orderId;
		}

		int64_t getFirstInstrOffsetInNextOrigInstr() {
			return (m_originalInstructionOffset + m_originalInstructionLength) << 8;
		}

		std::string printDebug() {
			std::string result;
			if (m_output)
				result += m_output->printDebug() + " = ";
			result += magic_enum::enum_name(m_id);
			if (m_input0)
				result += " " + m_input0->printDebug();
			if (m_input1)
				result += ", " + m_input1->printDebug();
			return result;
		}
	private:
		int m_originalInstructionOffset;
		int m_originalInstructionLength;
		int m_orderId;
	};

	class IRelatedToInstruction
	{
	public:
		virtual std::list<PCode::Instruction*> getInstructionsRelatedTo() = 0;
	};

	using DataValue = uint64_t;
};