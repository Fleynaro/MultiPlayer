#pragma once
#include <Code/Symbol/AbstractSymbol.h>

namespace CE::Symbol
{
	class AutoSdaSymbol : public AbstractSymbol
	{
	public:
		AutoSdaSymbol(Type type, SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "")
			: m_type(type), AbstractSymbol(manager, dataType, name, comment)
		{}

		Type getType() override {
			return m_type;
		}

	private:
		Type m_type;
	};
};