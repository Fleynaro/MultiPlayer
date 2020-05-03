#pragma once
#include <GhidraSync/DataTypeManager.h>
#include "TypeManager.h"
#include <DB/Mappers/TypedefTypeMapper.h>
#include <DB/Mappers/ClassTypeMapper.h>
#include <DB/Mappers/EnumTypeMapper.h>

using namespace CE;

TypeManager::TypeManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_dataTypeMapper = new DB::DataTypeMapper(this);
	addSystemTypes();
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

void TypeManager::addGhidraSystemTypes() {
	for (const auto& it : ghidraTypes) {
		createTypedef(it.second, it.first);
	}
}

void TypeManager::loadTypes() {
	m_dataTypeMapper->loadAll();
}

void TypeManager::loadClasses() {
	m_dataTypeMapper->loadAllClasses();
}

const std::string& TypeManager::getGhidraTypeName(DataType::Type* type) {
	for (const auto& it : ghidraTypes) {
		if (it.second->getId() == type->getId()) {
			return it.first;
		}
	}
	return getGhidraTypeName(getDefaultType());
}

DataType::Typedef* TypeManager::createTypedef(DataType::Type* refType, const std::string& name, const std::string& desc) {
	auto type = new DataType::Typedef(this, refType, name, desc);
	type->setMapper(m_dataTypeMapper->m_typedefTypeMapper);
	getProgramModule()->getTransaction()->markAsNew(type);
	return type;
}

DataType::Enum* TypeManager::createEnum(const std::string& name, const std::string& desc) {
	auto type = new DataType::Enum(this, name, desc);
	type->setMapper(m_dataTypeMapper->m_enumTypeMapper);
	getProgramModule()->getTransaction()->markAsNew(type);
	return type;
}

DataType::Class* TypeManager::createClass(const std::string& name, const std::string& desc) {
	auto type = new DataType::Class(this, name, desc);
	type->setMapper(m_dataTypeMapper->m_classTypeMapper);
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

DataType::Type* TypeManager::getType(DataType::Type* type, int pointer_lvl, int array_size) {
	if (pointer_lvl > 0) {
		for (int i = 0; i < pointer_lvl; i++) {
			type = new DataType::Pointer(this, type);
		}
	}

	if (array_size > 0) {
		type = new DataType::Array(this, type, array_size);
	}
	return type;
}

DataType::Type* TypeManager::getType(int type_id, int pointer_lvl, int array_size) {
	auto type = getTypeById(type_id);
	if (type != nullptr) {
		type = getType(type, pointer_lvl, array_size);
	}
	return type;
}

void TypeManager::setGhidraManager(Ghidra::DataTypeManager* ghidraManager) {
	m_ghidraManager = ghidraManager;
}

Ghidra::DataTypeManager* TypeManager::getGhidraManager() {
	return m_ghidraManager;
}

bool TypeManager::isGhidraManagerWorking() {
	return getGhidraManager() != nullptr;
}
