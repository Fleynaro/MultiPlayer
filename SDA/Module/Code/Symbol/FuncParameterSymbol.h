#pragma once
#include "AbstractSymbol.h"
#include "IMemorySymbol.h"

namespace CE::DataType {
	class Signature;
};

namespace CE::Symbol
{
	class FuncParameterSymbol : public AbstractSymbol, public IMemorySymbol
	{
		DataType::Signature* m_signature;
	public:
		FuncParameterSymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: AbstractSymbol(manager, type, name, comment)
		{}

		Type getType() override {
			return FUNC_PARAMETER;
		}

		std::list<Decompiler::Storage> getStorages() override;

		void setFuncSignature(DataType::Signature* signature);

		int getParameterIndex();
	};
};