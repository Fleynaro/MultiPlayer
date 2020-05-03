#include "AbstractType.h"
#include "Type.h"

using namespace CE;
using namespace CE::DataType;

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
	if (dereferencedType) {
		if (auto pointerType = dynamic_cast<Pointer*>(this)) {
			return pointerType->getType()->getBaseType();
		}
		if (auto arrayType = dynamic_cast<Array*>(this)) {
			return arrayType->getType()->getBaseType();
		}
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

bool Type::isPointer() {
	return getPointerLvl() != 0;
}

bool Type::isArray() {
	return getArraySize() != 0;
}

bool Type::isArrayOfPointers() {
	return isArray() && getPointerLvl() > 1;
}

bool Type::isArrayOfObjects() {
	return isArray() && getPointerLvl() == 1;
}

bool Type::isString() {
	if (getPointerLvl() == 0)
		return false;
	auto id = getBaseType()->getId();
	return id == SystemType::Char || id == SystemType::WChar;
}

bool Type::isSigned() {
	return false;
}

