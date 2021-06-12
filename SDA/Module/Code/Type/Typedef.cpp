#include "Typedef.h"
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::DataType;

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
	
	if (auto refTypeDef = dynamic_cast<Typedef*>(refType->getType())) {
		if (refTypeDef == this)
			return;
	}
	m_refType = refType;
}

DataTypePtr Typedef::getRefType() {
	return m_refType;
}
