#pragma once
#include "PCode/DecPCode.h"

namespace CE::Decompiler
{
	class Storage {
	public:
		enum StorageType {
			STORAGE_NONE,
			STORAGE_REGISTER,
			STORAGE_STACK,
			STORAGE_GLOBAL
		};

		Storage(StorageType storageType = STORAGE_NONE, int registerId = 0, int64_t offset = 0);

		StorageType getType();

		int getRegisterId();

		int64_t getOffset();
	private:
		StorageType m_storageType;
		int m_registerId;
		int64_t m_offset;
	};

	struct ParameterInfo {
		int m_index = 0;
		int m_size = 0;
		Storage m_storage;

		ParameterInfo() = default;

		ParameterInfo(int index, int size, Storage storage)
			: m_index(index), m_size(size), m_storage(storage)
		{}

		ParameterInfo(int size, Storage storage)
			: m_size(size), m_storage(storage)
		{}

		int getIndex();
	};
	using ReturnInfo = ParameterInfo;

	class FunctionCallInfo {
		std::list<ParameterInfo> m_paramInfos;
	public:
		FunctionCallInfo(std::list<ParameterInfo> paramInfos);

		std::list<ParameterInfo>& getParamInfos();

		ParameterInfo findParamInfoByIndex(int idx);

		ReturnInfo getReturnInfo();

		int findIndex(PCode::Register reg, int64_t offset);
	};

	static int GetIndex_FASTCALL(PCode::Register reg, int64_t offset) {
		if (reg.m_type == PCode::Register::Type::StackPointer) {
			return (int)offset / 0x8 - 5 + 1;
		}
		static std::map<PCode::RegisterId, int> regToParamId = {
			std::pair(ZYDIS_REGISTER_RCX, 1),
			std::pair(ZYDIS_REGISTER_ZMM0, 1),
			std::pair(ZYDIS_REGISTER_RDX, 2),
			std::pair(ZYDIS_REGISTER_ZMM1, 2),
			std::pair(ZYDIS_REGISTER_R8, 3),
			std::pair(ZYDIS_REGISTER_ZMM2, 3),
			std::pair(ZYDIS_REGISTER_R9, 4),
			std::pair(ZYDIS_REGISTER_ZMM3, 4),
		};
		auto it = regToParamId.find(reg.getGenericId());
		if (it != regToParamId.end()) {
			return it->second;
		}
		return -1;
	}
};