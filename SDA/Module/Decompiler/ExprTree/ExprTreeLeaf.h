#pragma once
#include "ExprTreeNode.h"
#include "../DecSymbol.h"
#include <Utility/Generic.h>

namespace CE::Decompiler::ExprTree
{
	class SymbolLeaf : public Node, public INumber
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

		bool isLeaf() override {
			return true;
		}

		ObjectHash::Hash getHash() override {
			return m_symbol->getHash();
		}

		Node* clone() override {
			return new SymbolLeaf(m_symbol);
		}

		std::string printDebug() override {
			return m_updateDebugInfo = m_symbol->printDebug();
		}
	};

	class NumberLeaf : public Node, public INumber
	{
	public:
		uint64_t m_value;

		NumberLeaf(uint64_t value)
			: m_value(value)
		{}

		NumberLeaf(double value, int size = 4)
		{
			if(size == 4)
				(float&)m_value = (float)value;
			else (double&)m_value = value;
		}

		BitMask64 getMask() override {
			return BitMask64(m_value);
		}

		bool isLeaf() override {
			return true;
		}

		ObjectHash::Hash getHash() override {
			ObjectHash hash;
			hash.addValue((int64_t&)m_value);
			return hash.getHash();
		}

		Node* clone() override {
			return new NumberLeaf(m_value);
		}

		std::string printDebug() override {
			return m_updateDebugInfo = ("0x" + Generic::String::NumberToHex(m_value) + "{"+ std::to_string((int)m_value) +"}");
		}
	};

	class FloatNanLeaf : public Node, public INumber, public IFloatingPoint
	{
	public:
		FloatNanLeaf()
		{}

		BitMask64 getMask() override {
			return BitMask64(8);
		}

		bool isLeaf() override {
			return true;
		}

		Node* clone() override {
			return this;
		}

		bool IsFloatingPoint() override {
			return true;
		}

		std::string printDebug() override {
			return m_updateDebugInfo = ("NaN");
		}
	};
};