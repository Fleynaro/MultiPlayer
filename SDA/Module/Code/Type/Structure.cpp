#include "Structure.h"
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::DataType;

Structure::Field::Field(Structure* structure, const std::string& name, DataTypePtr type, int offset, const std::string& comment)
	: m_structure(structure), m_offset(offset), Descrtiption(name, comment)
{
	setType(type);
}

int Structure::Field::getOffset() {
	return m_offset;
}

bool Structure::Field::isDefault() {
	return m_structure->getDefaultField() == this;
}

void Structure::Field::setType(DataTypePtr type) {
	m_type = type;
}

DataTypePtr Structure::Field::getType() {
	return m_type;
}

Structure::Structure(TypeManager* typeManager, const std::string& name, const std::string& comment)
	: UserType(typeManager, name, comment)
{
	m_defaultField = new Field(this, "undefined", GetUnit(getTypeManager()->getTypeByName("byte")), -1);
}

Structure::~Structure() {
	for (auto it : m_fields)
		delete it.second;
	delete m_defaultField;
}

Type::Group Structure::getGroup() {
	return Group::Structure;
}

int Structure::getSize() {
	return m_size;
}

void Structure::resize(int size) {
	m_size = size;
}

int Structure::getSizeByLastField() {
	if (m_fields.size() == 0)
		return 0;
	auto lastField = --m_fields.end();
	return lastField->first + lastField->second->getType()->getSize();
}

Structure::FieldMapType& Structure::getFields() {
	return m_fields;
}

int Structure::getNextEmptyBytesCount(int offset) {
	auto it = m_fields.upper_bound(offset);
	if (it != m_fields.end()) {
		return it->first - offset;
	}
	return m_size - offset;
}

bool Structure::areEmptyFields(int offset, int size) {
	if (offset < 0 || size <= 0)
		return false;

	if (getNextEmptyBytesCount(offset) < size)
		return false;

	return getFieldIterator(offset) == m_fields.end();
}

Structure::Field* Structure::getField(int offset) {
	auto it = getFieldIterator(offset);
	if (it != m_fields.end()) {
		return it->second;
	}
	return getDefaultField();
}

void Structure::addField(int offset, const std::string& name, DataTypePtr type, const std::string& desc) {
	m_fields.insert(std::make_pair(offset, new Field(this, name, type, offset, desc)));
	m_size = max(m_size, offset + type->getSize());
}

bool Structure::removeField(Field* field) {
	removeField(field->getOffset());
}

bool Structure::removeField(int offset) {
	auto it = getFieldIterator(offset);
	if (it != m_fields.end()) {
		m_fields.erase(it);
		return true;
	}
	return false;
}

bool Structure::moveField(int offset, int bytesCount) {
	auto field = getFieldIterator(offset);
	if (field == m_fields.end())
		return false;

	if (bytesCount > 0) {
		if (!areEmptyFields(field->first + field->second->getType()->getSize(), std::abs(bytesCount)))
			return false;
	}
	else {
		if (!areEmptyFields(field->first - std::abs(bytesCount), std::abs(bytesCount)))
			return false;
	}

	moveField_(offset, bytesCount);
	return true;
}

bool Structure::moveFields(int offset, int bytesCount) {
	int firstOffset = offset;
	int lastOffset = m_size - 1;
	if (!areEmptyFields((bytesCount > 0 ? lastOffset : firstOffset) - std::abs(bytesCount), std::abs(bytesCount)))
		return false;

	auto it = getFieldIterator(firstOffset);
	auto end = m_fields.end();
	if (bytesCount > 0) {
		end--;
		it--;
		std::swap(it, end);
	}
	while (it != end) {
		moveField_(it->first, bytesCount);
		if (bytesCount > 0)
			it--; else it++;
	}
	return true;
}

Structure::FieldMapType::iterator Structure::getFieldIterator(int offset) {
	auto it = m_fields.lower_bound(offset);
	if (it != m_fields.end()) {
		if (it->first <= offset && it->first + it->second->getType()->getSize() > offset) {
			return it;
		}
	}
	return m_fields.end();
}

Structure::Field* Structure::getDefaultField() {
	return m_defaultField;
}

void Structure::moveField_(int offset, int bytesCount) {
	auto field_ = m_fields.extract(offset);
	field_.key() += bytesCount;
	m_fields.insert(std::move(field_));
}
