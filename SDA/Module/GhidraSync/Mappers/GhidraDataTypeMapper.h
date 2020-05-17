#pragma once
#include <GhidraSync/GhidraAbstractMapper.h>
#include <Code/Type/UserType.h>

namespace CE {
	class TypeManager;
};

namespace CE::Ghidra
{
	using namespace ghidra;
	using namespace ghidra::datatype;

	class EnumTypeMapper;
	class StructureTypeMapper;
	class ClassTypeMapper;
	class TypedefTypeMapper;

	class DataTypeMapper : public IMapper
	{
	public:
		EnumTypeMapper* m_enumTypeMapper;
		StructureTypeMapper* m_structureTypeMapper;
		ClassTypeMapper* m_classTypeMapper;
		TypedefTypeMapper* m_typedefTypeMapper;
		CE::TypeManager* m_typeManager;

		DataTypeMapper(CE::TypeManager* typeManager);

		void load(packet::SDataLightSyncPacket* dataPacket) override;

		void load(packet::SDataFullSyncPacket* dataPacket) override;

		void upsert(SyncContext* ctx, IObject* obj) override;

		void remove(SyncContext* ctx, IObject* obj) override;

		datatype::SDataType buildDescToRemove(DataType::UserType* type);

		datatype::SDataType buildDesc(DataType::UserType* type);

		shared::STypeUnit buildTypeUnitDesc(DataTypePtr type);

		DataTypePtr getTypeByDesc(const shared::STypeUnit& typeUnitDesc);

		void changeUserTypeByDesc(DataType::UserType* type, const datatype::SDataType& typeDesc);
	};
};