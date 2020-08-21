#pragma once
#include "DecPCode.h"
#include <Utility/Generic.h>
#include "Utils/ObjectHash.h"

namespace CE::Decompiler {
	class DecompiledCodeGraph;
	namespace ExprTree {
		struct NodeCloneContext;
		class ReadValueNode;
		class FunctionCallContext;
		class SymbolLeaf;
	};
};

namespace CE::Decompiler::Symbol
{
	class SymbolWithId {
	public:
		int getId() {
			return m_id;
		}

		void setId(int id) {
			m_id = id;
		}

	private:
		int m_id = 0x0;
	};

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

		Symbol* clone(ExprTree::NodeCloneContext* ctx);

		virtual std::string printDebug() = 0;

	protected:
		virtual Symbol* cloneSymbol() = 0;

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

	class MemoryVariable : public Variable, public SymbolWithId, public PCode::IRelatedToInstruction
	{
	public:
		ExprTree::ReadValueNode* m_loadValueExpr = nullptr;
		
		MemoryVariable(ExprTree::ReadValueNode* loadValueExpr, int size)
			: m_loadValueExpr(loadValueExpr), Variable(size)
		{}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override;

		std::string printDebug() override {
			return "[mem_" + Generic::String::NumberToHex(getId()) + "_" + std::to_string(getSize() * 8) + "]";
		}

	protected:
		Symbol* cloneSymbol() override {
			return new MemoryVariable(m_loadValueExpr, getSize());
		}
	};

	class LocalVariable : public Variable, public SymbolWithId, public PCode::IRelatedToInstruction
	{
	public:
		std::list<PCode::Instruction*> m_instructionsRelatedTo;

		LocalVariable(ExtBitMask mask)
			: Variable(mask)
		{}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			return m_instructionsRelatedTo;
		}

		std::string printDebug() override {
			return "[var_" + Generic::String::NumberToHex(getId()) + "_" + std::to_string(getSize() * 8) + "]";
		}

	protected:
		Symbol* cloneSymbol() override {
			auto localVar = new LocalVariable(getMask());
			localVar->m_instructionsRelatedTo = m_instructionsRelatedTo;
			return localVar;
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

	protected:
		Symbol* cloneSymbol() override {
			return new RegisterVariable(m_register);
		}
	};

	class FunctionResultVar : public Variable, public SymbolWithId, public PCode::IRelatedToInstruction
	{
	public:
		ExprTree::FunctionCallContext* m_funcCallContext = nullptr;

		FunctionResultVar(ExprTree::FunctionCallContext* funcCallContext, ExtBitMask mask)
			: m_funcCallContext(funcCallContext), Variable(mask)
		{}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override;

		std::string printDebug() override;

	protected:
		Symbol* cloneSymbol() override {
			return new FunctionResultVar(m_funcCallContext, getMask());
		}
	};
};