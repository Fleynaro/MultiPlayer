#pragma once
#include "PCode/DecPCode.h"
#include <Utility/Generic.h>
#include "Utils/ObjectHash.h"

namespace CE::Decompiler {
	class DecompiledCodeGraph;
	namespace ExprTree {
		struct NodeCloneContext;
	};
};

namespace CE::Decompiler::Symbol
{
	class Symbol
	{
		ExtBitMask m_mask;
		DecompiledCodeGraph* m_decGraph;
	public:
		Symbol(ExtBitMask mask)
			: m_mask(mask)
		{}

		virtual ~Symbol();

		int getSize() {
			return m_mask.getSize();
		}

		ExtBitMask getMask() {
			return m_mask;
		}

		virtual ObjectHash::Hash getHash() = 0;

		void setDecGraph(DecompiledCodeGraph* decGraph) {
			m_decGraph = decGraph;
		}

		Symbol* clone(ExprTree::NodeCloneContext* ctx);

		virtual std::string printDebug() = 0;

	protected:
		virtual Symbol* cloneSymbol() = 0;
	};
	
	class RegisterVariable : public Symbol
	{
	public:
		PCode::Register m_register;

		RegisterVariable(PCode::Register reg)
			: m_register(reg), Symbol(reg.m_valueRangeMask)
		{}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue(m_register.getGenericId());
			hash.addValue((int64_t)m_register.m_valueRangeMask.getBitMask64().getValue());
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

	class AbstractVariable : public Symbol, public PCode::IRelatedToInstruction {
	public:
		AbstractVariable(ExtBitMask mask)
			: Symbol(mask)
		{}

		ObjectHash::Hash getHash() override {
			ObjectHash::Hash hash = 0;
			for (auto instr : getInstructionsRelatedTo())
				hash += 31 * instr->getOffset();
			return hash;
		}

		int getId() {
			return m_id;
		}

		void setId(int id) {
			m_id = id;
		}

	private:
		int m_id = 0x0;
	};

	class LocalVariable : public AbstractVariable
	{
	public:
		std::list<PCode::Instruction*> m_instructionsRelatedTo;

		LocalVariable(ExtBitMask mask)
			: AbstractVariable(mask)
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

	class MemoryVariable : public AbstractVariable
	{
	public:
		PCode::Instruction* m_instr;
		
		MemoryVariable(PCode::Instruction* instr, int size)
			: m_instr(instr), AbstractVariable(size)
		{}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			if(!m_instr)
				return {};
			return { m_instr };
		}

		std::string printDebug() override {
			return "[mem_" + Generic::String::NumberToHex(getId()) + "_" + std::to_string(getSize() * 8) + "]";
		}

	protected:
		Symbol* cloneSymbol() override {
			return new MemoryVariable(m_instr, getSize());
		}
	};

	class FunctionResultVar : public AbstractVariable
	{
	public:
		PCode::Instruction* m_instr;

		FunctionResultVar(PCode::Instruction* instr, ExtBitMask mask)
			: m_instr(instr), AbstractVariable(mask)
		{}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			if (!m_instr)
				return {};
			return { m_instr };
		}

		std::string printDebug() override {
			return "[funcVar_" + std::to_string(getId()) + "_" + std::to_string(getSize() * 8) + "]";
		}

	protected:
		Symbol* cloneSymbol() override {
			return new FunctionResultVar(m_instr, getMask());
		}
	};
};