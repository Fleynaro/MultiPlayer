#include "UserType.h"
#include <Utils/ObjectHash.h>

using namespace CE;
using namespace CE::DataType;

bool UserType::isUserDefined() {
	return true;
}

std::string UserType::getDisplayName() {
	return getName();
}

Ghidra::Id UserType::getGhidraId()
{
	ObjectHash objHash;
	objHash.addValue(getName());
	return objHash.getHash();
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
