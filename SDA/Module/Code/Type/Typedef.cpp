#include "Typedef.h"

CE::Type::Typedef::Typedef(Type* refType, int id, const std::string& name, const std::string& desc)
	: UserType(id, name, desc)
{
	setRefType(refType);
}

CE::Type::Typedef::Group CE::Type::Typedef::getGroup() {
	return Group::Typedef;
}

int CE::Type::Typedef::getSize() {
	if (getRefType() == this)
		return 0;
	return getRefType()->getSize();
}

std::string CE::Type::Typedef::getViewValue(void* addr) {
	if (getRefType() == this)
		return UserType::getViewValue(addr);
	return getRefType()->getViewValue(addr);
}

int CE::Type::Typedef::getPointerLvl() {
	if (getRefType() == this)
		return 0;
	return m_refType->getPointerLvl(); //MYTODO: не может быть указателя на массив
}

int CE::Type::Typedef::getArraySize() {
	if (getRefType() == this)
		return 0;
	return m_refType->getArraySize();
}

void CE::Type::Typedef::setRefType(Type* refType) {
	m_refType = refType;
}

CE::Type::Type* CE::Type::Typedef::getRefType() {
	return m_refType;
}
