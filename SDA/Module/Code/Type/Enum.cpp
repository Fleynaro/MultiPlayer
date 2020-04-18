#include "Enum.h"

int CE::Type::Enum::getSize() {
	return m_size;
}

void CE::Type::Enum::setSize(int size) {
	m_size = size;
}

CE::Type::Enum::Group CE::Type::Enum::getGroup() {
	return Group::Enum;
}

std::string CE::Type::Enum::getViewValue(void* addr) {
	auto value = m_fields.find(*(int*)(addr));
	if (value == m_fields.end())
		return UserType::getViewValue(addr);
	return value->second + " (" + UserType::getViewValue(addr) + ")";
}

CE::Type::Enum::FieldDict& CE::Type::Enum::getFieldDict() {
	return m_fields;
}

bool CE::Type::Enum::removeField(int value) {
	auto it = m_fields.find(value);
	if (it != m_fields.end()) {
		m_fields.erase(it);
		return true;
	}
	return false;
}

void CE::Type::Enum::addField(std::string name, int value) {
	m_fields[value] = name;
}

void CE::Type::Enum::deleteAll() {
	m_fields.clear();
}
