#pragma once
#include "PCode/DecPCode.h"
#include <Utility/Generic.h>
#include <Utils/HashSerialization.h>

namespace CE::Decompiler {
	class DecompiledCodeGraph;
	namespace ExprTree {
		struct NodeCloneContext;
	};
};

namespace CE::Decompiler::Symbol
{
	// symbol of decompiler level that has some concrete value (low-level, before symbolization)
	class Symbol
	{
	public:
		Symbol(int size)
			: m_size(size)
		{}

		virtual ~Symbol() {}

		int getSize() {
			return m_size;
		}

		virtual HS getHash() = 0;

		Symbol* clone(ExprTree::NodeCloneContext* ctx);

		virtual std::string printDebug() = 0;

	protected:
		int m_size;

		virtual Symbol* cloneSymbol() = 0;
	};
	
	// variable that is associated with the register and dont contain direct expr. value
	class RegisterVariable : public Symbol
	{
	public:
		PCode::Register m_register;

		RegisterVariable(PCode::Register reg)
			: m_register(reg), Symbol(reg.getSize())
		{}

		HS getHash() override {
			return HS()
				<< m_register.getId()
				<< m_register.m_valueRangeMask.getValue();
		}

		std::string printDebug() override {
			return "[reg_" + m_register.printDebug() + "]";
		}

	protected:
		Symbol* cloneSymbol() override {
			return new RegisterVariable(m_register);
		}
	};

	// variable on high-level
	class AbstractVariable : public Symbol, public PCode::IRelatedToInstruction {
	public:
		AbstractVariable(int size)
			: Symbol(size)
		{}

		HS getHash() override {
			HS hs;
			for (auto instr : getInstructionsRelatedTo())
				hs = hs + (HS() << instr->getOffset());
			return hs;
		}

		int getId() {
			return getHash().getHashValue() % 10000;
		}
	};

	// variable that is used because impossible to use expr. value directly from register (there are if/else/for)
	class LocalVariable : public AbstractVariable
	{
	public:
		std::list<PCode::Instruction*> m_instructionsRelatedTo;

		LocalVariable(int size)
			: AbstractVariable(size)
		{}

		void setSize(int size) {
			m_size = size;
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			return m_instructionsRelatedTo;
		}

		std::string printDebug() override {
			return "[var_" + Generic::String::NumberToHex(getId()) + "_" + std::to_string(getSize() * 8) + "]";
		}

	protected:
		Symbol* cloneSymbol() override {
			auto localVar = new LocalVariable(getSize());
			localVar->m_instructionsRelatedTo = m_instructionsRelatedTo;
			return localVar;
		}
	};

	// variable that contains value from some memory location
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

	// variable that has a result of some function call
	class FunctionResultVar : public AbstractVariable
	{
	public:
		PCode::Instruction* m_instr;

		FunctionResultVar(PCode::Instruction* instr, int size)
			: m_instr(instr), AbstractVariable(size)
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
			return new FunctionResultVar(m_instr, getSize());
		}
	};
};