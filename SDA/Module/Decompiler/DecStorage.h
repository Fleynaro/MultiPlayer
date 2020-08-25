#pragma once

namespace CE::Decompiler
{
	class Storage {
	public:
		enum StorageType {
			STORAGE_REGISTER,
			STORAGE_STACK,
			STORAGE_GLOBAL
		};

		Storage(StorageType storageType, int registerId, int offset)
			: m_storageType(storageType), m_registerId(registerId), m_offset(offset)
		{}

		StorageType getType() {
			return m_storageType;
		}

		int getRegisterId() {
			return m_registerId;
		}

		int getOffset() {
			return m_offset;
		}
	private:
		StorageType m_storageType;
		int m_registerId;
		int m_offset;
	};

	class ParameterStorage : public Storage {
	public:
		ParameterStorage(int index, StorageType storageType, int registerId, int offset)
			: m_index(index), Storage(storageType, registerId, offset)
		{}

		int getIndex() {
			return m_index;
		}
	private:
		int m_index;
	};

	struct ParameterInfo {
		int m_size;
		ParameterStorage m_storage;

		ParameterInfo(int size, ParameterStorage storage)
			: m_size(size), m_storage(storage)
		{}
	};

	class FunctionCallInfo {
		std::list<ParameterInfo> m_paramInfos;
	public:
		FunctionCallInfo(std::list<ParameterInfo> paramInfos)
			: m_paramInfos(paramInfos)
		{}

		std::list<ParameterInfo>& getParamInfos() {
			return m_paramInfos;
		}
	};
};