#pragma once
#include "ExprTreeNode.h"
#include "../DecSymbol.h"
#include <Utility/Generic.h>

namespace CE::Decompiler::ExprTree
{
	class ILeaf : public virtual INode
	{};

	class SymbolLeaf : public Node, public ILeaf
	{
	public:
		Symbol::Symbol* m_symbol;

		SymbolLeaf(Symbol::Symbol* symbol)
			: m_symbol(symbol)
		{}
		
		BitMask64 getMask() override {
			return m_symbol->getMask().getBitMask64().withoutOffset();
		}

		HS getHash() override {
			return m_symbol->getHash();
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

		BitMask64 getMask() override {
			return BitMask64(getValue());
		}
	};

	class NumberLeaf : public Node, public INumberLeaf
	{
		uint64_t m_value;
	public:
		NumberLeaf(uint64_t value)
			: m_value(value)
		{}

		NumberLeaf(double value, int size = 4)
		{
			if(size == 4)
				(float&)m_value = (float)value;
			else (double&)m_value = value;
		}

		uint64_t getValue() override {
			return m_value;
		}

		void setValue(uint64_t value) override {
			m_value = value;
		}

		INode* clone(NodeCloneContext* ctx) override {
			return new NumberLeaf(m_value);
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