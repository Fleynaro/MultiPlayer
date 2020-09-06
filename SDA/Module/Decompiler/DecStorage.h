#pragma once
#include <main.h>

namespace CE::Decompiler
{
	class Storage {
	public:
		enum StorageType {
			STORAGE_REGISTER,
			STORAGE_STACK,
			STORAGE_GLOBAL
		};

		Storage(StorageType storageType, int registerId, int offset);

		StorageType getType();

		int getRegisterId();

		int getOffset();
	private:
		StorageType m_storageType;
		int m_registerId;
		int m_offset;
	};

	class ParameterStorage : public Storage {
	public:
		ParameterStorage(int index, StorageType storageType, int registerId, int offset);

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