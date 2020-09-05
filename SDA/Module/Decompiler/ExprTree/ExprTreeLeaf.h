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
		{
			m_symbol->m_symbolLeafs.push_back(this);
		}

		~SymbolLeaf() {
			m_symbol->m_symbolLeafs.remove(this);
		}

		BitMask64 getMask() override {
			return m_symbol->getMask().getBitMask64().withoutOffset();
		}

		ObjectHash::Hash getHash() override {
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

		BitMask64 getMask() override {
			return BitMask64(m_value);
		}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue((int64_t&)m_value);
			return hash.getHash();
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

		ObjectHash::Hash getHash() override {
			return 0xF1F1F1F1;
		}

		INode* clone(NodeCloneContext* ctx) override {
			return this;
		}

		bool isFloatingPoint() override {
			return true;
		}

		std::string printDebug() override {
			return m_updateDebugInfo = ("NaN");
		}
	};
};