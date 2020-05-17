#include "GhidraDataTypeMapper.h"
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::Ghidra;

void markObjectAsSynced(SyncContext* ctx, DataType::UserType* type) {
	SQLite::Statement query(*ctx->m_db, "UPDATE sda_types SET ghidra_sync_id=?1 WHERE id=?2");
	query.bind(1, ctx->m_syncId);
	query.bind(2, type->getId());
	query.exec();
}

void DataTypeMapper::upsert(SyncContext* ctx, IObject* obj) {
	auto type = static_cast<DataType::UserType*>(obj);
	markObjectAsSynced(ctx, type);
}

void DataTypeMapper::remove(SyncContext* ctx, IObject* obj) {
	auto type = static_cast<DataType::UserType*>(obj);
	markObjectAsSynced(ctx, type);
}

datatype::SDataType DataTypeMapper::buildDescToRemove(DataType::UserType* type) {
	datatype::SDataType typeDesc;
	typeDesc.__set_id(type->getGhidraId());
	typeDesc.__set_size(0);
	return typeDesc;
}

datatype::SDataType DataTypeMapper::buildDesc(DataType::UserType* type) {
	datatype::SDataType typeDesc;
	typeDesc.__set_id(type->getGhidraId());
	typeDesc.__set_group((datatype::DataTypeGroup::type)type->getGroup());
	typeDesc.__set_size(type->getSize());
	typeDesc.__set_name(type->getName());
	typeDesc.__set_desc(type->getComment());
	return typeDesc;
}

shared::STypeUnit DataTypeMapper::buildTypeUnitDesc(DataTypePtr type) {
	shared::STypeUnit typeUnitDesc;
	typeUnitDesc.__set_typeId(m_typeManager->getGhidraId(type->getType()));
	/*typeUnitDesc.__set_pointerLvl(type->getPointerLvl());
	typeUnitDesc.__set_arraySize(type->getArraySize());*/
	return typeUnitDesc;
}

DataTypePtr* DataTypeMapper::getTypeByDesc(const shared::STypeUnit& typeUnitDesc) {
	return nullptr;//m_typeManager->getType(findTypeById(typeUnitDesc.typeId), typeUnitDesc.pointerLvl, typeUnitDesc.arraySize);
}
