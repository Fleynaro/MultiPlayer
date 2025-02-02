#include "GhidraStructureTypeMapper.h"
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::Ghidra;

StructureTypeMapper::StructureTypeMapper(DataTypeMapper* dataTypeMapper)
	: m_dataTypeMapper(dataTypeMapper)
{}

void StructureTypeMapper::load(packet::SDataFullSyncPacket* dataPacket) {
	for (auto structDesc : dataPacket->structures) {
		auto type = m_dataTypeMapper->m_typeManager->getTypeByGhidraId(structDesc.type.id);
		if (type == nullptr)
			throw std::exception("item not found");
		if (auto structure = dynamic_cast<DataType::Structure*>(type)) {
			changeStructureByDesc(structure, structDesc);
		}
	}
}

void StructureTypeMapper::upsert(SyncContext* ctx, IObject* obj) {
	auto type = static_cast<DataType::Structure*>(obj);
	ctx->m_dataPacket->structures.push_back(buildDesc(type));
	m_dataTypeMapper->upsert(ctx, obj);
}

void StructureTypeMapper::remove(SyncContext* ctx, IObject* obj) {
	m_dataTypeMapper->remove(ctx, obj);
}

datatype::SDataTypeStructure StructureTypeMapper::buildDesc(DataType::Structure* Struct) {
	datatype::SDataTypeStructure structDesc;
	structDesc.__set_type(m_dataTypeMapper->buildDesc(Struct));
	for (auto it : Struct->getFields()) {
		auto field = it.second;
		datatype::SDataTypeStructureField structFieldDesc;
		structFieldDesc.__set_name(field->getName());
		structFieldDesc.__set_offset(field->getOffset());
		structFieldDesc.__set_type(m_dataTypeMapper->buildTypeUnitDesc(field->getDataType()));
		structFieldDesc.__set_comment(field->getComment());
		structDesc.fields.push_back(structFieldDesc);
	}
	return structDesc;
}

void StructureTypeMapper::changeStructureByDesc(DataType::Structure* Struct, const datatype::SDataTypeStructure& structDesc) {
	m_dataTypeMapper->changeUserTypeByDesc(Struct, structDesc.type);
	Struct->getFields().clear();
	for (auto fieldDesc : structDesc.fields) {
		Struct->addField(fieldDesc.offset, fieldDesc.name, m_dataTypeMapper->getTypeByDesc(fieldDesc.type), fieldDesc.comment);
	}
}
