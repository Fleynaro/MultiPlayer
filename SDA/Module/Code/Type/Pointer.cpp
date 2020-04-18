#include "Pointer.h"

CE::Type::Pointer::Pointer(Type* type)
	: m_type(type)
{
	if (type->isArray())
		throw std::logic_error("Pointer cannot point at an array.");
	m_type->addOwner();
}

CE::Type::Pointer::~Pointer() {
	m_type->free();
}

CE::Type::Pointer::Group CE::Type::Pointer::getGroup() {
	return getType()->getGroup();
}

bool CE::Type::Pointer::isUserDefined() {
	return getType()->isUserDefined();
}

int CE::Type::Pointer::getId() {
	return getType()->getId();
}

std::string CE::Type::Pointer::getName() {
	return getType()->getName();
}

std::string CE::Type::Pointer::getDesc() {
	return getType()->getDesc();
}

std::string CE::Type::Pointer::getDisplayName() {
	return getType()->getDisplayName() + "*";
}

int CE::Type::Pointer::getSize() {
	return 8;
}

std::string CE::Type::Pointer::getViewValue(void* addr) {
	return "(" + getDisplayName() + ")0x" + Generic::String::NumberToHex(*(uint64_t*)addr);
}

CE::Type::Type* CE::Type::Pointer::getType() {
	return m_type;
}

int CE::Type::Pointer::getPointerLvl() {
	return getType()->getPointerLvl() + 1;
}

int CE::Type::Pointer::getArraySize() {
	return 0;
}
