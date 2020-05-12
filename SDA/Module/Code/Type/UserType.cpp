#include "UserType.h"

using namespace CE;
using namespace CE::DataType;

UserType::UserType(TypeManager* typeManager, const std::string& name, const std::string& comment)
	: Type(typeManager, name, comment)
{}

bool UserType::isUserDefined() {
	return true;
}

std::string UserType::getDisplayName() {
	return getName();
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
