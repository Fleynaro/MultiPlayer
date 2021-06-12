#pragma once
#include "AbstractSymbol.h"
#include "IMemorySymbol.h"

namespace CE::DataType {
	class IFunctionSignature;
};

namespace CE::Symbol
{
	class FuncParameterSymbol : public AbstractSymbol, public IMemorySymbol
	{
		int m_paramIdx;
		DataType::IFunctionSignature* m_signature;
	public:
		FuncParameterSymbol(SymbolManager* manager, int paramIdx, DataType::IFunctionSignature* signature, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: m_paramIdx(paramIdx), m_signature(signature), AbstractSymbol(manager, type, name, comment)
		{}

		int getParamIdx() {
			return m_paramIdx;
		}

		Type getType() override {
			return FUNC_PARAMETER;
		}

		Decompiler::Storage getStorage() override {
			auto paramIdx = getParamIdx();
			for (auto& paramInfo : m_signature->getCallInfo().getParamInfos()) {
				if (paramIdx == paramInfo.getIndex()) {
					return paramInfo.m_storage;
				}
			}
			return Decompiler::Storage();
		}

		void setFuncSignature(DataType::IFunctionSignature* signature) {
			m_signature = signature;
		}
	};
};