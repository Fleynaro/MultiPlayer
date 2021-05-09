#pragma once
#include "ExprTreeNode.h"
#include "../DecSymbol.h"

namespace CE::Decompiler::ExprTree
{
	class ILeaf : public virtual INode
	{};

	class SymbolLeaf : public Node, public ILeaf, public PCode::IRelatedToInstruction
	{
	public:
		Symbol::Symbol* m_symbol;

		SymbolLeaf(Symbol::Symbol* symbol)
			: m_symbol(symbol)
		{}
		
		BitMask64 getMask() override {
			return m_symbol->getMask().withoutOffset();
		}

		HS getHash() override {
			return m_symbol->getHash();
		}

		std::list<PCode::Instruction*> getInstructionsRelatedTo() override {
			if (auto symbolRelToInstr = dynamic_cast<PCode::IRelatedToInstruction*>(m_symbol))
				return symbolRelToInstr->getInstructionsRelatedTo();
			return {};
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new SymbolLeaf(m_symbol->clone(ctx));
		}

		std::string printDebug() override {
			return m_updateDebugInfo = m_symbol->printDebug();
		}
	};

	class INumberLeaf : public ILeaf
	{
	public:
		virtual uint64_t getValue() = 0;

		virtual void setValue(uint64_t value) = 0;

		HS getHash() override {
			return HS() << getValue();
		}
	};

	class NumberLeaf : public Node, public INumberLeaf
	{
		uint64_t m_value;
		BitMask64 m_rangeValueMask;
	public:

		NumberLeaf(uint64_t value, BitMask64 rangeValueMask)
			: m_value(value & rangeValueMask.getValue()), m_rangeValueMask(rangeValueMask)
		{}

		NumberLeaf(double value, BitMask64 rangeValueMask)
			: m_rangeValueMask(rangeValueMask)
		{
			if(rangeValueMask.getSize() == 4)
				(float&)m_value = (float)value;
			else (double&)m_value = value;
		}

		uint64_t getValue() override {
			return m_value;
		}

		void setValue(uint64_t value) override {
			m_value = value;
		}

		BitMask64 getMask() override {
			return m_value;
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new NumberLeaf(m_value, m_rangeValueMask);
		}

		std::string printDebug() override {
			return m_updateDebugInfo = ("0x" + Generic::String::NumberToHex(m_value) + "{"+ std::to_string((int)m_value) +"}");
		}
	};

	class FloatNanLeaf : public Node
	{
	public:
		FloatNanLeaf()
		{}

		BitMask64 getMask() override {
			return BitMask64(8);
		}

		HS getHash() override {
			return HS();
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new FloatNanLeaf();
		}

		bool isFloatingPoint() override {
			return true;
		}

		std::string printDebug() override {
			return m_updateDebugInfo = ("NaN");
		}
	};
};