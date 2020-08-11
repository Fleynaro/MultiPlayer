#pragma once
#include "TypeManager.h"
#include <DB/Mappers/TypedefTypeMapper.h>
#include <DB/Mappers/StructureTypeMapper.h>
#include <DB/Mappers/ClassTypeMapper.h>
#include <DB/Mappers/EnumTypeMapper.h>
#include <DB/Mappers/SignatureTypeMapper.h>
#include <GhidraSync/Mappers/GhidraTypedefTypeMapper.h>
#include <GhidraSync/Mappers/GhidraStructureTypeMapper.h>
#include <GhidraSync/Mappers/GhidraClassTypeMapper.h>
#include <GhidraSync/Mappers/GhidraEnumTypeMapper.h>
#include <GhidraSync/Mappers/GhidraSignatureTypeMapper.h>
#include <Utils/ObjectHash.h>

using namespace CE;

TypeManager::TypeManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_dataTypeMapper = new DB::DataTypeMapper(this);
	m_ghidraDataTypeMapper = new Ghidra::DataTypeMapper(this);
	addSystemTypes();
	addGhidraTypedefs();
}

TypeManager::~TypeManager() {
	delete m_dataTypeMapper;
	delete m_ghidraDataTypeMapper;
}

void TypeManager::addSystemTypes() {
	m_items.insert({
		std::make_pair(DataType::SystemType::Void, new DataType::Void),
		std::make_pair(DataType::SystemType::Bool, new DataType::Bool),
		std::make_pair(DataType::SystemType::Byte, new DataType::Byte),
		std::make_pair(DataType::SystemType::Int8, new DataType::Int8),
		std::make_pair(DataType::SystemType::Int16, new DataType::Int16),
		std::make_pair(DataType::SystemType::Int32, new DataType::Int32),
		std::make_pair(DataType::SystemType::Int64, new DataType::Int64),
		std::make_pair(DataType::SystemType::UInt16, new DataType::UInt16),
		std::make_pair(DataType::SystemType::UInt32, new DataType::UInt32),
		std::make_pair(DataType::SystemType::UInt64, new DataType::UInt64),
		std::make_pair(DataType::SystemType::UInt128, new DataType::UInt128),
		std::make_pair(DataType::SystemType::Float, new DataType::Float),
		std::make_pair(DataType::SystemType::Double, new DataType::Double),
		std::make_pair(DataType::SystemType::Char, new DataType::Char),
		std::make_pair(DataType::SystemType::WChar, new DataType::WChar)
		});

	Iterator it(this);
	while (it.hasNext()) {
		auto type = it.next();
		type->setTypeManager(this);
	}
}

void TypeManager::addGhidraTypedefs() {
	static std::pair<std::string, DB::Id> typedefs[] = {
		std::make_pair("void", DataType::SystemType::Void),
		std::make_pair("unicode", DataType::SystemType::Void),
		std::make_pair("string", DataType::SystemType::Void),
		std::make_pair("IMAGE_RICH_HEADER", DataType::SystemType::Void),

		std::make_pair("uchar", DataType::SystemType::Byte),
		std::make_pair("uint8_t", DataType::SystemType::Byte),
		std::make_pair("undefined1", DataType::SystemType::Int8),
		std::make_pair("TerminatedCString", DataType::SystemType::Char),

		std::make_pair("short", DataType::SystemType::Int16),
		std::make_pair("ushort", DataType::SystemType::UInt16),
		std::make_pair("word", DataType::SystemType::Int16),
		std::make_pair("undefined2", DataType::SystemType::Int16),

		std::make_pair("int", DataType::SystemType::Int32),
		std::make_pair("uint", DataType::SystemType::UInt32),
		std::make_pair("long", DataType::SystemType::Int32),
		std::make_pair("ulong", DataType::SystemType::UInt32),
		std::make_pair("dword", DataType::SystemType::Int32),
		std::make_pair("float", DataType::SystemType::Float),
		std::make_pair("ImageBaseOffset32", DataType::SystemType::UInt32),
		std::make_pair("undefined4", DataType::SystemType::Int32),

		std::make_pair("longlong", DataType::SystemType::Int64),
		std::make_pair("ulonglong", DataType::SystemType::UInt64),
		std::make_pair("qword", DataType::SystemType::Int64),
		std::make_pair("double", DataType::SystemType::Double),
		std::make_pair("undefined8", DataType::SystemType::Int64),

		std::make_pair("GUID", DataType::SystemType::UInt128)
	};

	DB::Id startId = 100;
	for (const auto& it : typedefs) {
		auto type = new DataType::Typedef(this, it.first);
		type->setId(startId);
		type->setGhidraMapper(m_ghidraDataTypeMapper->m_typedefTypeMapper);
		type->setRefType(DataType::GetUnit(getTypeById(it.second)));
		m_items.insert(std::make_pair(startId, type));
		startId++;
	}
}

void TypeManager::loadBefore() {
	m_dataTypeMapper->loadBefore();
}

void TypeManager::loadAfter() {
	m_dataTypeMapper->loadAfter();
}

void TypeManager::loadTypesFrom(ghidra::packet::SDataFullSyncPacket* dataPacket) {
	m_ghidraDataTypeMapper->load(dataPacket);
}

DataType::Typedef* TypeManager::createTypedef(const std::string& name, const std::string& desc) {
	auto type = new DataType::Typedef(this, name, desc);
	type->setMapper(m_dataTypeMapper->m_typedefTypeMapper);
	type->setGhidraMapper(m_ghidraDataTypeMapper->m_typedefTypeMapper);
	type->setId(m_dataTypeMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(type);
	return type;
}

DataType::Enum* TypeManager::createEnum(const std::string& name, const std::string& desc) {
	auto type = new DataType::Enum(this, name, desc);
	type->setMapper(m_dataTypeMapper->m_enumTypeMapper);
	type->setGhidraMapper(m_ghidraDataTypeMapper->m_enumTypeMapper);
	type->setId(m_dataTypeMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(type);
	return type;
}

DataType::Structure* TypeManager::createStructure(const std::string& name, const std::string& desc) {
	auto type = new DataType::Structure(this, name, desc);
	type->setMapper(m_dataTypeMapper->m_structureTypeMapper);
	type->setGhidraMapper(m_ghidraDataTypeMapper->m_structureTypeMapper);
	type->setId(m_dataTypeMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(type);
	return type;
}

DataType::Class* TypeManager::createClass(const std::string& name, const std::string& desc) {
	auto type = new DataType::Class(this, name, desc);
	type->setMapper(m_dataTypeMapper->m_classTypeMapper);
	type->setGhidraMapper(m_ghidraDataTypeMapper->m_classTypeMapper);
	type->setId(m_dataTypeMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(type);
	return type;
}

DataType::Signature* TypeManager::createSignature(const std::string& name, const std::string& desc) {
	auto type = new DataType::Signature(this, name, desc);
	type->setMapper(m_dataTypeMapper->m_signatureTypeMapper);
	type->setGhidraMapper(m_ghidraDataTypeMapper->m_signatureTypeMapper);
	type->setId(m_dataTypeMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(type);
	return type;
}

DataType::Type* TypeManager::getDefaultType() {
	return getTypeById(DataType::SystemType::Byte);
}

DataType::Type* TypeManager::getDefaultReturnType() {
	return getTypeById(DataType::SystemType::Void);
}

DataType::Type* TypeManager::getTypeById(DB::Id id) {
	return static_cast<DataType::Type*>(find(id));
}

DataType::Type* TypeManager::getTypeByName(const std::string& typeName)
{
	Iterator it(this);
	while (it.hasNext()) {
		auto type = it.next();
		if (type->getName() == typeName) {
			return type;
		}
	}
	return nullptr;
}

DataType::Type* TypeManager::getTypeByGhidraId(Ghidra::Id id) {
	Iterator it(this);
	while (it.hasNext()) {
		auto type = it.next();
		if (getGhidraId(type) == id) {
			return type;
		}
	}
	return nullptr;
}

Ghidra::Id TypeManager::getGhidraId(DataType::Type* type) {
	if (auto userType = dynamic_cast<DataType::UserType*>(type)) {
		return userType->getGhidraId();
	}
	
	ObjectHash objHash;
	objHash.addValue(type->getName());
	return objHash.getHash();
}