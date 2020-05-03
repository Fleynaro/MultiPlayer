#include "Typedef.h"

using namespace CE;
using namespace CE::DataType;

Typedef::Typedef(TypeManager* typeManager, Type* refType, const std::string& name, const std::string& desc)
	: UserType(typeManager, name, desc)
{
	setRefType(refType);
}

Typedef::Group Typedef::getGroup() {
	return Group::Typedef;
}

int Typedef::getSize() {
	if (getRefType() == this)
		return 0;
	return getRefType()->getSize();
}

std::string Typedef::getViewValue(void* addr) {
	if (getRefType() == this)
		return UserType::getViewValue(addr);
	return getRefType()->getViewValue(addr);
}

int Typedef::getPointerLvl() {
	if (getRefType() == this)
		return 0;
	return m_refType->getPointerLvl(); //MYTODO: не может быть указателя на массив
}

int Typedef::getArraySize() {
	if (getRefType() == this)
		return 0;
	return m_refType->getArraySize();
}

void Typedef::setRefType(Type* refType) {
	m_refType = refType;
}

Type* Typedef::getRefType() {
	return m_refType;
}
