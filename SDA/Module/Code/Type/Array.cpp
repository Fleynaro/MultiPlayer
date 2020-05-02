#include "Array.h"

using namespace CE;
using namespace CE::DataType;

std::string Array::getDisplayName() {
	return getType()->getDisplayName() + "[" + std::to_string(getArraySize()) + "]";
}

int Array::getSize() {
	return getArraySize() * getType()->getSize();
}

int Array::getArraySize() {
	return static_cast<int>(m_arraySize);
}

int Array::getItemSize() {
	return getType()->getSize();
}
