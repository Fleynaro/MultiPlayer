#include "GhidraClassTypeMapper.h"
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::Ghidra;

ClassTypeMapper::ClassTypeMapper(StructureTypeMapper* structTypeMapper)
	: m_structTypeMapper(structTypeMapper)
{}

void ClassTypeMapper::load(DataSyncPacket* dataPacket) {
	for (auto classDesc : dataPacket->m_classes) {
		auto type = m_structTypeMapper->m_dataTypeMapper->m_typeManager->getTypeByGhidraId(classDesc.structType.type.id);
		if (type == nullptr) {
			type = m_structTypeMapper->m_dataTypeMapper->m_typeManager->createClass(classDesc.structType.type.name, classDesc.structType.type.comment);
		}
		changeClassByDesc(static_cast<DataType::Class*>(type), classDesc);
	}
}

void ClassTypeMapper::upsert(SyncContext* ctx, IObject* obj) {
	auto type = static_cast<DataType::Class*>(obj);
	ctx->m_dataPacket->m_classes.push_back(buildDesc(type));
	m_structTypeMapper->upsert(ctx, obj);
}

void ClassTypeMapper::remove(SyncContext* ctx, IObject* obj) {
	m_structTypeMapper->remove(ctx, obj);
}

datatype::SDataTypeClass ClassTypeMapper::buildDesc(DataType::Class* Class) {
	datatype::SDataTypeClass classDesc;
	classDesc.__set_structType(m_structTypeMapper->buildDesc(Class));
	return classDesc;
}

void ClassTypeMapper::changeClassByDesc(DataType::Class* Class, const datatype::SDataTypeClass& classDesc) {
	m_structTypeMapper->changeStructureByDesc(Class, classDesc.structType);
}
