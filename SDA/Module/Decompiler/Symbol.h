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

	class GlobalVar : public Symbol
	{
	public:
		int m_offset;

		GlobalVar(int offset, uint64_t )
			: m_offset(offset)
		{}

		std::string printDebug() override {
			return "[global:" + std::to_string(m_offset) + "]";
		}
	};

	class LocalStackVar : public Symbol
	{
	public:
		int m_stackOffset;
		int m_size;

		LocalStackVar(int stackOffset, int size)
			: m_stackOffset(stackOffset), m_size(size)
		{}

		int getSize() override {
			return m_size;
		}

		std::string printDebug() override {
			return "[stack_"+ Generic::String::NumberToHex(m_stackOffset) +"_"+ std::to_string(m_size * 8) +"]";
		}
	};

	class LocalRegVar : public Symbol
	{
	public:
		ZydisRegister m_register;

		LocalRegVar(ZydisRegister reg)
			: m_register(reg)
		{}

		std::string printDebug() override {
			return "[reg_" + std::string(ZydisRegisterGetString(m_register)) + "]";
		}
	};

	class FunctionResultVar : public Symbol
	{
	public:
		ExprTree::FunctionCallContext* m_funcCallContext;

		FunctionResultVar(ExprTree::FunctionCallContext* funcCallContext)
			: m_funcCallContext(funcCallContext)
		{}

		std::string printDebug() override;
	};

	class Parameter : public Symbol
	{
	public:
		int m_idx = 0;
		bool m_isVector;
		Parameter(int idx, bool isVector = false)
			: m_idx(idx), m_isVector(isVector)
		{}

		std::string printDebug() override {
			return "[param_" + std::to_string(m_idx) + "]";
		}
	};
};