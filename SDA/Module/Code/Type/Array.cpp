#include "Array.h"


std::string CE::Type::Array::getDisplayName() {
	return getType()->getDisplayName() + "[" + std::to_string(getArraySize()) + "]";
}

int CE::Type::Array::getSize() {
	return getArraySize() * getType()->getSize();
}

int CE::Type::Array::getArraySize() {
	return static_cast<int>(m_arraySize);
}

int CE::Type::Array::getItemSize() {
	return getType()->getSize();
}
