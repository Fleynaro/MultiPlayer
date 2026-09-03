#include "FuncParameterSymbol.h"
#include "../Type/FunctionSignature.h"

using namespace CE;
using namespace CE::Symbol;

Decompiler::Storage FuncParameterSymbol::getStorage() {
	auto paramIdx = getParameterIndex();
	for (auto& paramInfo : m_signature->getCallInfo().getParamInfos()) {
		if (paramIdx == paramInfo.getIndex()) {
			return paramInfo.m_storage;
		}
	}
	return Decompiler::Storage();
}

void FuncParameterSymbol::setFuncSignature(DataType::Signature* signature) {
	m_signature = signature;
}

int FuncParameterSymbol::getParameterIndex() {
	int idx = 1;
	for (auto param : m_signature->getParameters()) {
		if (this == param) {
			return idx;
		}
		idx++;
	}
	return 0;
}
