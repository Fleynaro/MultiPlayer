#include "AbstractType.h"
#include "Type.h"

using namespace CE;
using namespace CE::DataType;

Type::Type(TypeManager* typeManager, const std::string& name, const std::string& comment)
	: m_typeManager(typeManager), Descrtiption(name, comment)
{}

std::string Type::getViewValue(void* addr) {
	uint64_t mask = 0x0;
	for (int i = 0; i < max(8, getSize()); i++)
		mask |= 0xFF << i;
	return std::to_string(*(uint64_t*)addr & mask);
}

std::string Type::getViewValue(uint64_t value) {
	return getViewValue(&value);
}

Type* Type::getBaseType(bool refType, bool dereferencedType) {
	if (auto unit = dynamic_cast<DataType::Unit*>(this)) {
		return unit->getType()->getBaseType();
	}
	if (refType) {
		if (auto typeDef = dynamic_cast<DataType::Typedef*>(this)) {
			return typeDef->getRefType()->getBaseType();
		}
	}
	return this;
}

bool Type::isSystem() {
	return !isUserDefined();
}

bool Type::isSigned() {
	return false;
}

void Type::setTypeManager(TypeManager* typeManager) {
	m_typeManager = typeManager;
}

TypeManager* Type::getTypeManager() {
	return m_typeManager;
}

