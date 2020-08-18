#pragma once
#include "DecPCode.h"
#include <Utility/Generic.h>
#include "Utils/ObjectHash.h"

namespace CE::Decompiler {
	class DecompiledCodeGraph;
	namespace ExprTree {
		class ReadValueNode;
		class FunctionCallContext;
		class SymbolLeaf;
	};
};

namespace CE::Decompiler::Symbol
{
	class Symbol
	{
	public:
		std::list<ExprTree::SymbolLeaf*> m_symbolLeafs;

		virtual ~Symbol();

		virtual int getSize() {
			return 8;
		}

		virtual ExtBitMask getMask() {
			return ExtBitMask(getSize());
		}

		virtual ObjectHash::Hash getHash() {
			ObjectHash hash;
			hash.addValue((int64_t)this);
			return hash.getHash();
		}

		void setDecGraph(DecompiledCodeGraph* decGraph) {
			m_decGraph = decGraph;
		}

		virtual std::string printDebug() = 0;

	private:
		DecompiledCodeGraph* m_decGraph;
	};

	class Variable : public Symbol
	{
	public:
		Variable(ExtBitMask mask)
			: m_mask(mask)
		{}

		int getSize() override {
			return m_mask.getSize();
		}

		ExtBitMask getMask() override {
			return m_mask;
		}
	private:
		ExtBitMask m_mask;
	};

	class MemoryVariable : public Variable, public PCode::IRelatedToInstruction
	{
	public:
		int m_id;
		ExprTree::ReadValueNode* m_loadValueExpr;
		
		MemoryVariable(ExprTree::ReadValueNode* loadValueExpr, int size)
			: m_loadValueExpr(loadValueExpr), Variable(size)
		{
			static int id = 1;
			m_id = id++;
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override;

		std::string printDebug() override {
			return "[mem_" + Generic::String::NumberToHex(m_id) + "_" + std::to_string(getSize() * 8) + "]";
		}
	};

	class LocalVariable : public Variable, public PCode::IRelatedToInstruction
	{
	public:
		int m_id;
		std::list<PCode::Instruction*> m_instructionsRelatedTo;

		LocalVariable(ExtBitMask mask)
			: Variable(mask)
		{
			static int id = 1;
			m_id = id++;
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			return m_instructionsRelatedTo;
		}

		std::string printDebug() override {
			return "[var_" + Generic::String::NumberToHex(m_id) + "_" + std::to_string(getSize() * 8) + "]";
		}
	};

	class RegisterVariable : public Variable
	{
	public:
		PCode::Register m_register;

		RegisterVariable(PCode::Register reg)
			: m_register(reg), Variable(reg.m_valueRangeMask)
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

	class FunctionResultVar : public Variable, public PCode::IRelatedToInstruction
	{
	public:
		int m_id;
		ExprTree::FunctionCallContext* m_funcCallContext;

		FunctionResultVar(ExprTree::FunctionCallContext* funcCallContext, ExtBitMask mask)
			: m_funcCallContext(funcCallContext), Variable(mask)
		{
			static int id = 1;
			m_id = id++;
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override;

		std::string printDebug() override;
	};
};