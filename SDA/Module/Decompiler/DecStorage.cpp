#include "DecStorage.h"

using namespace CE;
using namespace CE::Decompiler;

FunctionCallInfo::FunctionCallInfo(std::list<ParameterInfo> paramInfos)
	: m_paramInfos(paramInfos)
{}

std::list<ParameterInfo>& FunctionCallInfo::getParamInfos() {
	return m_paramInfos;
}

ParameterInfo& FunctionCallInfo::findParamInfoByIndex(int idx) {
	for (auto& paramInfo : getParamInfos()) {
		if (idx == paramInfo.m_storage.getIndex()) {
			return paramInfo;
		}
	}
	throw std::exception("not found");
}

ParameterInfo::ParameterInfo(int size, ParameterStorage storage)
	: m_size(size), m_storage(storage)
{}

ParameterStorage::ParameterStorage(int index, StorageType storageType, int registerId, int64_t offset)
	: m_index(index), Storage(storageType, registerId, offset)
{}

int ParameterStorage::getIndex() {
	return m_index;
}

Storage::Storage(StorageType storageType, int registerId, int64_t offset)
	: m_storageType(storageType), m_registerId(registerId), m_offset(offset)
{}

Storage::StorageType Storage::getType() {
	return m_storageType;
}

int Storage::getRegisterId() {
	return m_registerId;
}

int64_t Storage::getOffset() {
	return m_offset;
}
