#include "UserType.h"

using namespace CE;
using namespace CE::DataType;

UserType::UserType(TypeManager* typeManager, std::string name, std::string desc)
	: Type(typeManager), m_name(name), m_desc(desc)
{}

bool UserType::isUserDefined() {
	return true;
}

std::string UserType::getDisplayName() {
	return getName();
}

std::string UserType::getName() {
	return m_name;
}

std::string UserType::getDesc() {
	return m_desc;
}

void UserType::setName(const std::string& name) {
	m_name = name;
}

void UserType::setDesc(const std::string& desc) {
	m_desc = desc;
}

bool UserType::isGhidraUnit() {
	return m_ghidraUnit;
}

void UserType::setGhidraUnit(bool toggle) {
	m_ghidraUnit = toggle;
}

DB::Id UserType::getId() {
	return m_id;
}

void UserType::setId(DB::Id id) {
	m_id = id;
}

DB::IMapper* UserType::getMapper() {
	return m_mapper;
}

void UserType::setMapper(DB::IMapper* mapper) {
	m_mapper = mapper;
}
