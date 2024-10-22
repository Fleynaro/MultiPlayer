#pragma once
#include "GhidraDataTypeMapper.h"
#include <Code/Type/Enum.h>

namespace CE::Ghidra
{
	class EnumTypeMapper : public IMapper
	{
	public:
		EnumTypeMapper(DataTypeMapper* dataTypeMapper);

		void load(packet::SDataFullSyncPacket* dataPacket) override;

		void upsert(SyncContext* ctx, IObject* obj) override;

		void remove(SyncContext* ctx, IObject* obj) override;

	private:
		DataTypeMapper* m_dataTypeMapper;

		datatype::SDataTypeEnum buildDesc(DataType::Enum* Enum);

		void changeEnumByDesc(DataType::Enum* Enum, const datatype::SDataTypeEnum& enumDesc);
	};
};