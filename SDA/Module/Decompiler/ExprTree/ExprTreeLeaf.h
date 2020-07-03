#pragma once
#include "ExprTreeNode.h"
#include "../Symbol.h"
#include <Utility/Generic.h>

namespace CE::Decompiler::ExprTree
{
	class SymbolLeaf : public Node, public INumber
	{
	public:
		Symbol::Symbol* m_symbol;

		SymbolLeaf(Symbol::Symbol* symbol)
			: m_symbol(symbol)
		{}

		uint64_t getMask() override {
			return GetMaskBySize(m_symbol->getSize());
		}

		bool isLeaf() override {
			return true;
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

		uint64_t getMask() override {
			return m_value;
		}

		bool isLeaf() override {
			return true;
		}

		std::string printDebug() override {
			return m_updateDebugInfo = ("0x" + Generic::String::NumberToHex(m_value) + "{"+ std::to_string((int)m_value) +"}");
		}
	};
};