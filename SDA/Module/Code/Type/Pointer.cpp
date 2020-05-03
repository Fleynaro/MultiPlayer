#include "Pointer.h"

using namespace CE;
using namespace CE::DataType;

Pointer::Pointer(Type* type)
	: m_type(type)
{
	if (type->isArray())
		throw std::logic_error("Pointer cannot point at an array.");
	m_type->addOwner();
}

DB::Id Pointer::getId() {
	return m_type->getId();
}

void Pointer::setId(DB::Id id) {
	m_type->setId(id);
}

Pointer::~Pointer() {
	m_type->free();
}

Pointer::Group Pointer::getGroup() {
	return getType()->getGroup();
}

bool Pointer::isUserDefined() {
	return getType()->isUserDefined();
}

std::string Pointer::getName() {
	return getType()->getName();
}

std::string Pointer::getDesc() {
	return getType()->getDesc();
}

std::string Pointer::getDisplayName() {
	return getType()->getDisplayName() + "*";
}

int Pointer::getSize() {
	return 8;
}

std::string Pointer::getViewValue(void* addr) {
	return "(" + getDisplayName() + ")0x" + Generic::String::NumberToHex(*(uint64_t*)addr);
}

Type* Pointer::getType() {
	return m_type;
}

int Pointer::getPointerLvl() {
	return getType()->getPointerLvl() + 1;
}

int Pointer::getArraySize() {
	return 0;
}

DB::Id Pointer::getId() {
	return m_type->getId();
}

void Pointer::setId(DB::Id id) {
	return m_type->setId(id);
}

DB::AbstractMapper* Pointer::getMapper() {
	return m_type->getMapper();
}

void Pointer::setMapper(DB::AbstractMapper* mapper) {
	m_type->setMapper(mapper);
}
