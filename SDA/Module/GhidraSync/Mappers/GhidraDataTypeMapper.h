#pragma once
#include <GhidraSync/GhidraAbstractMapper.h>
#include <Code/Type/UserType.h>
#include "DataTypeManagerService.h"

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
		DataTypeMapper(CE::TypeManager* typeManager)
			: m_typeManager(typeManager)
		{}

		void load(DataPacket* dataPacket) override {

		}

		void upsert(SyncContext* ctx, IObject* obj) override;

		void remove(SyncContext* ctx, IObject* obj) override;

		datatype::SDataType buildDescToRemove(DataType::UserType* type);

		datatype::SDataType buildDesc(DataType::UserType* type);

		shared::STypeUnit buildTypeUnitDesc(DataTypePtr type);

		DataTypePtr* getTypeByDesc(const shared::STypeUnit& typeUnitDesc);

	private:
		CE::TypeManager* m_typeManager;
	};
};