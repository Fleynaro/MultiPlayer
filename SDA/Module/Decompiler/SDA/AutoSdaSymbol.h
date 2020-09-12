#pragma once
#include <Code/Symbol/AbstractSymbol.h>

namespace CE::Symbol
{
	class AutoSdaSymbol : public AbstractSymbol
	{
		Type m_type;
		int64_t m_value;
		std::list<int64_t> m_instrOffsets;
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
	};

	class AutoSdaMemSymbol : public AutoSdaSymbol, public IMemorySymbol
	{
		int64_t m_offset;
	public:
		AutoSdaMemSymbol(Type type, int64_t offset, std::list<int64_t> instrOffsets, SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "")
			: AutoSdaSymbol(type, 0, instrOffsets, manager, dataType, name, comment), m_offset(offset)
		{}

		int64_t getOffset() override {
			return m_offset;
		}
	};
};