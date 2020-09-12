#pragma once
#include <Code/Symbol/AbstractSymbol.h>

namespace CE::Symbol
{
	class AutoSdaSymbol : public AbstractSymbol
	{
	public:
		AutoSdaSymbol(Type type, int64_t value, std::list<int64_t> instrOffsets, SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "")
			: m_type(type), m_value(value), m_instrOffsets(instrOffsets), AbstractSymbol(manager, dataType, name, comment)
		{}

		Type getType() override {
			return m_type;
		}

		std::list<int64_t> getInstrOffsets() {
			return m_instrOffsets;
		}
	private:
		Type m_type;
		int64_t m_value;
		std::list<int64_t> m_instrOffsets;
	};

	class AutoSdaMemSymbol : public AutoSdaSymbol
	{
	public:
		AutoSdaMemSymbol(Type type, int64_t value, std::list<int64_t> instrOffsets, SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "")
			: AutoSdaSymbol(type, value, instrOffsets, manager, dataType, name, comment)
		{}

		
	};
};