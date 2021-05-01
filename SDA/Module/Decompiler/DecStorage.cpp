#include "DecStorage.h"

using namespace CE;
using namespace CE::Decompiler;
using namespace CE::Decompiler::PCode;

FunctionCallInfo::FunctionCallInfo(std::list<ParameterInfo> paramInfos)
	: m_paramInfos(paramInfos)
{}

std::list<ParameterInfo>& FunctionCallInfo::getParamInfos() {
	return m_paramInfos;
}

ParameterInfo FunctionCallInfo::findParamInfoByIndex(int idx) {
	for (auto& paramInfo : getParamInfos()) {
		if (idx == paramInfo.getIndex()) {
			return paramInfo;
		}
	}
	return ParameterInfo(0, 0, Storage());
}

ReturnInfo FunctionCallInfo::getReturnInfo() {
	return findParamInfoByIndex(0);
}

int FunctionCallInfo::findIndex(Register reg, int64_t offset) {
	for (auto paramInfo : m_paramInfos) {
		auto& storage = paramInfo.m_storage;
		if (storage.getType() == Storage::STORAGE_REGISTER && reg.getGenericId() == storage.getRegisterId() || (offset == storage.getOffset() &&
			(storage.getType() == Storage::STORAGE_STACK && reg.m_type == Register::Type::StackPointer ||
				storage.getType() == Storage::STORAGE_GLOBAL && reg.m_type == Register::Type::InstructionPointer))) {
			return paramInfo.getIndex();
		}
	}
	return -1;
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

int ParameterInfo::getIndex() {
	return m_index;
}
