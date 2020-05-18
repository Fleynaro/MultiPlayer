#include "GhidraDataTypeMapper.h"
#include "GhidraEnumTypeMapper.h"
#include "GhidraStructureTypeMapper.h"
#include "GhidraClassTypeMapper.h"
#include "GhidraTypedefTypeMapper.h"
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::Ghidra;

DataTypeMapper::DataTypeMapper(CE::TypeManager* typeManager)
	: m_typeManager(typeManager)
{
	m_enumTypeMapper = new EnumTypeMapper(this);
	m_structureTypeMapper = new StructureTypeMapper(this);
	m_classTypeMapper = new ClassTypeMapper(m_structureTypeMapper);
	m_typedefTypeMapper = new TypedefTypeMapper(this);
}

void DataTypeMapper::createTypeByDescIfNotExists(const datatype::SDataType& typeDesc)
{
	auto type = m_typeManager->getTypeByGhidraId(typeDesc.id);
	if (type == nullptr) {
		createTypeByDesc(typeDesc);
	}
}

DataType::UserType* DataTypeMapper::createTypeByDesc(const datatype::SDataType& typeDesc)
{
	DataType::UserType* userType = nullptr;
	switch (typeDesc.group)
	{
	case DataTypeGroup::Typedef:
		userType = m_typeManager->createTypedef(typeDesc.name, typeDesc.comment);
		break;
	case DataTypeGroup::Enum:
		userType = m_typeManager->createEnum(typeDesc.name, typeDesc.comment);
		break;
	case DataTypeGroup::Structure:
		userType = m_typeManager->createStructure(typeDesc.name, typeDesc.comment);
		break;
	case DataTypeGroup::Class:
		userType = m_typeManager->createClass(typeDesc.name, typeDesc.comment);
		break;
	}
	return userType;
}

void DataTypeMapper::load(packet::SDataFullSyncPacket* dataPacket) {
	for (auto it : dataPacket->typedefs) {
		createTypeByDescIfNotExists(it.type);
	}
	
	for (auto it : dataPacket->enums) {
		createTypeByDescIfNotExists(it.type);
	}

	for (auto it : dataPacket->structures) {
		createTypeByDescIfNotExists(it.type);
	}

	for (auto it : dataPacket->classes) {
		createTypeByDescIfNotExists(it.structType.type);
	}

	m_typedefTypeMapper->load(dataPacket);
	m_enumTypeMapper->load(dataPacket);
	m_structureTypeMapper->load(dataPacket);
	m_classTypeMapper->load(dataPacket);
}

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
	typeDesc.__set_comment(type->getComment());
	return typeDesc;
}

shared::STypeUnit DataTypeMapper::buildTypeUnitDesc(DataTypePtr type) {
	shared::STypeUnit typeUnitDesc;
	typeUnitDesc.__set_typeId(m_typeManager->getGhidraId(type->getType()));
	for (auto lvl : type->getPointerLevels()) {
		typeUnitDesc.pointerLvls.push_back((int16_t)lvl);
	}
	return typeUnitDesc;
}

DataTypePtr DataTypeMapper::getTypeByDesc(const shared::STypeUnit& desc) {
	std::vector<int> ptr_levels;
	for (auto lvl : desc.pointerLvls) {
		ptr_levels.push_back((int)lvl);
	}
	
	auto type = m_typeManager->getTypeByGhidraId(desc.typeId);
	if (type == nullptr) {
		type = m_typeManager->getDefaultType();
	}
	return std::make_shared<DataType::Unit>(type, ptr_levels);
}

void DataTypeMapper::changeUserTypeByDesc(DataType::UserType* type, const datatype::SDataType& typeDesc) {
	type->setName(typeDesc.name);
	if (typeDesc.comment != "{pull}") {
		type->setComment(typeDesc.comment);
	}
}
