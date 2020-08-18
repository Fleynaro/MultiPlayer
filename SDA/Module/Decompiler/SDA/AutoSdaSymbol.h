#pragma once
#include <Code/Symbol/AbstractSymbol.h>

namespace CE::Symbol
{
	class AutoSdaSymbol : public AbstractSymbol
	{
	public:
		AutoSdaSymbol(Type type, int value, SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "")
			: m_type(type), m_value(value), AbstractSymbol(manager, dataType, name, comment)
		{}

		Type getType() override {
			return m_type;
		}

	private:
		Type m_type;
		int m_value;
	};
};