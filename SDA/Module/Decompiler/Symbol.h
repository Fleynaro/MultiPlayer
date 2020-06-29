#pragma once
#include "main.h"
#include <inttypes.h>
#include <Zycore/Format.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>
#include <Utility/Generic.h>

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
		ZydisRegister m_register;

		RegisterVariable(ZydisRegister reg, int size)
			: m_register(reg), Variable(size)
		{}

		std::string printDebug() override {
			return "[reg_" + std::string(ZydisRegisterGetString(m_register)) + "_" + std::to_string(getSize() * 8) + "]";
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
		ExprTree::FunctionCallContext* m_funcCallContext;

		FunctionResultVar(ExprTree::FunctionCallContext* funcCallContext, int size)
			: m_funcCallContext(funcCallContext), Variable(size)
		{}

		std::string printDebug() override;
	};
};