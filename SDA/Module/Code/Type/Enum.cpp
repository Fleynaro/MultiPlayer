#include "Enum.h"

using namespace CE;
using namespace CE::DataType;

Enum::Enum(std::string name, std::string desc)
	: UserType(name, desc)
{}

int Enum::getSize() {
	return m_size;
}

void Enum::setSize(int size) {
	m_size = size;
}

Enum::Group Enum::getGroup() {
	return Group::Enum;
}

std::string Enum::getViewValue(void* addr) {
	auto value = m_fields.find(*(int*)(addr));
	if (value == m_fields.end())
		return UserType::getViewValue(addr);
	return value->second + " (" + UserType::getViewValue(addr) + ")";
}

Enum::FieldDict& Enum::getFieldDict() {
	return m_fields;
}

bool Enum::removeField(int value) {
	auto it = m_fields.find(value);
	if (it != m_fields.end()) {
		m_fields.erase(it);
		return true;
	}
	return false;
}

void Enum::addField(std::string name, int value) {
	m_fields[value] = name;
}

void Enum::deleteAll() {
	m_fields.clear();
}
