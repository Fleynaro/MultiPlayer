#pragma once
#include "DecPCode.h"
#include <Utility/Generic.h>
#include "Utils/ObjectHash.h"

namespace CE::Decompiler::ExprTree {
	class Node;
	class FunctionCallContext;
	class SymbolLeaf;
};

namespace CE::Decompiler::Symbol
{
	class Symbol
	{
	public:
		std::list<ExprTree::SymbolLeaf*> m_symbolLeafs;

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

	class MemoryVariable : public Variable
	{
	public:
		int m_id;
		ExprTree::Node* m_loadValueExpr;
		
		MemoryVariable(ExprTree::Node* loadValueExpr, int size)
			: m_loadValueExpr(loadValueExpr), Variable(size)
		{
			static int id = 1;
			m_id = id++;
		}

		std::string printDebug() override {
			return "[mem_" + Generic::String::NumberToHex(m_id) + "_" + std::to_string(getSize() * 8) + "]";
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
			return "[reg_" + m_register.printDebug() + "]";
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