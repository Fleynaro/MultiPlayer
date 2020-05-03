#pragma once
#include <GhidraSync/DataTypeManager.h>
#include "TypeManager.h"
#include <DB/Mappers/TypedefTypeMapper.h>
#include <DB/Mappers/ClassTypeMapper.h>
#include <DB/Mappers/EnumTypeMapper.h>

using namespace CE;

TypeManager::TypeManager(ProgramModule* module)
	: AbstractItemManager(module)
{}

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
}

void TypeManager::addGhidraSystemTypes() {
	for (const auto& it : ghidraTypes) {
		createTypedef(it.second, it.first);
	}
}

DataType::Typedef* TypeManager::createTypedef(DataType::Type* refType, const std::string& name, const std::string& desc) {
	auto type = new DataType::Typedef(refType, name, desc);
	type->setMapper(m_dataTypeMapper->m_typedefTypeMapper);
	getProgramModule()->getTransaction()->markAsNew(type);
	return type;
}

DataType::Enum* TypeManager::createEnum(const std::string& name, const std::string& desc) {
	auto type = new DataType::Enum(name, desc);
	type->setMapper(m_dataTypeMapper->m_enumTypeMapper);
	getProgramModule()->getTransaction()->markAsNew(type);
	return type;
}

DataType::Class* TypeManager::createClass(const std::string& name, const std::string& desc) {
	auto type = new DataType::Class(name, desc);
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

DataType::Type* TypeManager::getType(DataType::Type* type, int pointer_lvl, int array_size) {
	if (pointer_lvl > 0) {
		for (int i = 0; i < pointer_lvl; i++) {
			type = new DataType::Pointer(type);
		}
	}

	if (array_size > 0) {
		type = new DataType::Array(type, array_size);
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
