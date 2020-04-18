#include "AbstractType.h"
#include "Type.h"


void CE::Type::Type::free() {
	m_ownerCount--;
	if (m_ownerCount == 0) {
		m_isDeleted = true;
		delete this;
	}
	else if (m_ownerCount < 0) {
		if (m_isDeleted)
			throw std::logic_error("Double deleting. Trying to delete already deleted type.");
		else throw std::logic_error("m_ownerCount < 0. The lack of calling addOwner somewhere.");
	}
}

std::string CE::Type::Type::getViewValue(void* addr) {
	uint64_t mask = 0x0;
	for (int i = 0; i < max(8, getSize()); i++)
		mask |= 0xFF << i;
	return std::to_string(*(uint64_t*)addr & mask);
}

std::string CE::Type::Type::getViewValue(uint64_t value) {
	return getViewValue(&value);
}

CE::Type::Type* CE::Type::Type::getBaseType(bool refType, bool dereferencedType) {
	if (dereferencedType) {
		if (auto pointerType = dynamic_cast<CE::Type::Pointer*>(this)) {
			return pointerType->getType()->getBaseType();
		}
		if (auto arrayType = dynamic_cast<CE::Type::Array*>(this)) {
			return arrayType->getType()->getBaseType();
		}
	}
	if (refType) {
		if (auto typeDef = dynamic_cast<CE::Type::Typedef*>(this)) {
			return typeDef->getRefType()->getBaseType();
		}
	}
	return this;
}

bool CE::Type::Type::isSystem() {
	return !isUserDefined();
}

bool CE::Type::Type::isPointer() {
	return getPointerLvl() != 0;
}

bool CE::Type::Type::isArray() {
	return getArraySize() != 0;
}

bool CE::Type::Type::isArrayOfPointers() {
	return isArray() && getPointerLvl() > 1;
}

bool CE::Type::Type::isArrayOfObjects() {
	return isArray() && getPointerLvl() == 1;
}

bool CE::Type::Type::isString() {
	if (getPointerLvl() == 0)
		return false;
	auto id = getBaseType()->getId();
	return id == CE::Type::SystemType::Char || id == CE::Type::SystemType::WChar;
}

bool CE::Type::Type::isSigned() {
	return false;
}

void CE::Type::Type::addOwner() {
	m_ownerCount++;
}