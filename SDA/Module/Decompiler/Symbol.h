#pragma once
#include "DecPCode.h"
#include <Utility/Generic.h>
#include "Utils/ObjectHash.h"

namespace CE::Decompiler::ExprTree {
	class FunctionCallContext;
};

namespace CE::Decompiler::Symbol
{
	class Symbol
	{
	public:
		virtual int getSize() {
			return 8;
		}

		virtual ObjectHash::Hash getHash() {
			ObjectHash hash;
			hash.addValue((int64_t)this);
			return hash.getHash();
		}

		virtual std::string printDebug() = 0;
	};

	class Variable : public Symbol
	{
	public:
		Variable(int size)
			: m_size(size)
		{}

		int getSize() override {
			return m_size;
		}
	private:
		int m_size;
	};

	class GlobalVariable : public Variable
	{
	public:
		int m_offset;

		GlobalVariable(int offset, int size)
			: m_offset(offset), Variable(size)
		{}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue(m_offset);
			return hash.getHash();
		}

		std::string printDebug() override {
			return "[global_" + std::to_string(m_offset) + "_" + std::to_string(getSize() * 8) + "]";
		}
	};

	class LocalVariable : public Variable
	{
	public:
		int m_id;

		LocalVariable(int size)
			: Variable(size)
		{
			static int id = 1;
			m_id = id++;
		}

		std::string printDebug() override {
			return "[var_" + Generic::String::NumberToHex(m_id) + "_" + std::to_string(getSize() * 8) + "]";
		}
	};

	class StackVariable : public Variable
	{
	public:
		int m_stackOffset;

		StackVariable(int stackOffset, int size)
			: m_stackOffset(stackOffset), Variable(size)
		{}

		std::string printDebug() override {
			return "[stack_"+ std::string(m_stackOffset < 0 ? "-" : "") + Generic::String::NumberToHex(std::abs(m_stackOffset)) +"_"+ std::to_string(getSize() * 8) +"]";
		}
	};

	class RegisterVariable : public Variable
	{
	public:
		PCode::Register m_register;

		RegisterVariable(PCode::Register reg, int size)
			: m_register(reg), Variable(size)
		{}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue(m_register.getGenericId());
			hash.addValue((int64_t&)m_register.m_valueRangeMask);
			return hash.getHash();
		}

		std::string printDebug() override {
			auto reg = (ZydisRegister)m_register.m_genericId;
			if (reg == ZYDIS_REGISTER_RFLAGS) {
				std::string flagName = "flag";
				auto flag = (ZydisCPUFlag)GetShiftValueOfMask(m_register.m_valueRangeMask);
				if (flag == ZYDIS_CPUFLAG_CF)
					flagName = "CF";
				else if (flag == ZYDIS_CPUFLAG_OF)
					flagName = "OF";
				else if (flag == ZYDIS_CPUFLAG_SF)
					flagName = "SF";
				else if (flag == ZYDIS_CPUFLAG_ZF)
					flagName = "ZF";
				return "[reg_" + flagName + "_8]";
			}
			return "[reg_" + std::string(ZydisRegisterGetString(reg)) + "_" + std::to_string(getSize() * 8) + "]";
		}
	};

	class ParameterVariable : public Variable
	{
	public:
		int m_index = 0;

		ParameterVariable(int index, int size)
			: m_index(index), Variable(size)
		{}

		std::string printDebug() override {
			return "[param_" + std::to_string(m_index) + "_" + std::to_string(getSize() * 8) + "]";
		}
	};

	class FunctionResultVar : public Variable
	{
	public:
		int m_id;
		ExprTree::FunctionCallContext* m_funcCallContext;

		FunctionResultVar(ExprTree::FunctionCallContext* funcCallContext, int size)
			: m_funcCallContext(funcCallContext), Variable(size)
		{
			static int id = 1;
			m_id = id++;
		}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue(m_id);
			return hash.getHash();
		}

		std::string printDebug() override;
	};
};