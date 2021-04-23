#include "FuncParameterSymbol.h"
#include "../Type/FunctionSignature.h"

using namespace CE;
using namespace CE::Symbol;

std::list<Decompiler::Storage> FuncParameterSymbol::getStorages() {
	std::list<Decompiler::Storage> storages;
	auto paramIdx = getParameterIndex();
	for (auto& paramInfo : m_signature->getParameterInfos()) {
		if (paramIdx == paramInfo.m_storage.getIndex()) {
			storages.push_back(paramInfo.m_storage);
		}
	}
	return storages;
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