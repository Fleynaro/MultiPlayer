#include "Typedef.h"

using namespace CE;
using namespace CE::DataType;

Typedef::Typedef(TypeManager* typeManager, const std::string& name, const std::string& comment)
	: UserType(typeManager, name, comment)
{}

Typedef::Group Typedef::getGroup() {
	return Group::Typedef;
}

int Typedef::getSize() {
	if (getRefType()->getType() == this)
		return 0;
	return getRefType()->getSize();
}

std::string Typedef::getViewValue(void* addr) {
	if (getRefType()->getType() == this)
		return UserType::getViewValue(addr);
	return getRefType()->getViewValue(addr);
}

void Typedef::setRefType(DataTypePtr refType) {
	m_refType = refType;
}

DataTypePtr Typedef::getRefType() {
	return m_refType;
}
