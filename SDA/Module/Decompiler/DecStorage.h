#pragma once
#include <main.h>

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

	class ParameterStorage : public Storage {
	public:
		ParameterStorage(int index, StorageType storageType, int registerId, int64_t offset);

		int getIndex();
	private:
		int m_index;
	};

	struct ParameterInfo {
		int m_size;
		ParameterStorage m_storage;

		ParameterInfo(int size, ParameterStorage storage);
	};

	class FunctionCallInfo {
		std::list<ParameterInfo> m_paramInfos;
	public:
		FunctionCallInfo(std::list<ParameterInfo> paramInfos);

		std::list<ParameterInfo>& getParamInfos();

		ParameterInfo& findParamInfoByIndex(int idx);
	};
};