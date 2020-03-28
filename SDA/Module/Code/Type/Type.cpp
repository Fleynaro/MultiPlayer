#include "Type.h"

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

bool CE::Type::Type::isString() {
	if (getPointerLvl() == 0)
		return false;
	auto id = getBaseType()->getId();
	return id == CE::Type::SystemType::Char || id == CE::Type::SystemType::WChar;
}
