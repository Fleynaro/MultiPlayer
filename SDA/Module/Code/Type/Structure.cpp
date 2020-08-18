#include "Structure.h"
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::DataType;

Structure::Field::Field(Structure* structure, const std::string& name, DataTypePtr type, int absBitOffset, int bitSize, const std::string& comment)
	: m_structure(structure), m_absBitOffset(absBitOffset), m_bitSize(bitSize), Descrtiption(name, comment)
{
	setDataType(type);
}

int Structure::Field::getBitSize() {
	return m_bitSize;
}

int Structure::Field::getBitOffset() {
	return m_absBitOffset - getOffset() * 0x8;
}

int Structure::Field::getSize() {
	return m_type->getSize();
}

int Structure::Field::getOffset() {
	auto byteOffset = m_absBitOffset / 0x8;
	return byteOffset - (isBitField() ? (byteOffset % getSize()) : 0);
}

bool Structure::Field::isBitField() {
	return (m_bitSize % 0x8) != 0 || (m_absBitOffset % 0x8) != 0;
}

bool Structure::Field::isDefault() {
	return m_structure->getDefaultField() == this;
}

void Structure::Field::setDataType(DataTypePtr type) {
	m_type = type;
}

DataTypePtr Structure::Field::getDataType() {
	return m_type;
}

Structure::Structure(TypeManager* typeManager, const std::string& name, const std::string& comment)
	: UserType(typeManager, name, comment)
{
	m_defaultField = new Field(this, "undefined", GetUnit(getTypeManager()->getTypeByName("byte")), -1, -1);
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
	if (m_fields.empty())
		return 0;
	auto lastField = std::prev(m_fields.end())->second;
	return lastField->getOffset() + lastField->getSize();
}

Structure::FieldMapType& Structure::getFields() {
	return m_fields;
}

int Structure::getNextEmptyBitsCount(int bitOffset) {
	auto it = m_fields.upper_bound(bitOffset);
	if (it != m_fields.end()) {
		return it->first - bitOffset;
	}
	return m_size - bitOffset;
}

bool Structure::areEmptyFields(int bitOffset, int bitSize) {
	if (bitOffset < 0 || bitSize <= 0)
		return false;

	//check free space to the next field starting at the bitOffset
	if (getNextEmptyBitsCount(bitOffset) < bitSize)
		return false;

	//check intersecting with an existing field at the bitOffset
	return getFieldIterator(bitOffset) == m_fields.end();
}

bool Structure::areEmptyFieldsInBytes(int offset, int size) {
	return areEmptyFields(offset * 0x8, size * 0x8);
}

Structure::Field* Structure::getField(int bitOffset) {
	auto it = getFieldIterator(bitOffset);
	if (it != m_fields.end()) {
		return it->second;
	}
	return getDefaultField();
}

void Structure::addField(int offset, const std::string& name, DataTypePtr type, const std::string& desc) {
	addField(offset * 0x8, type->getSize() * 0x8, name, type, desc);
}

void Structure::addField(int bitOffset, int bitSize, const std::string& name, DataTypePtr type, const std::string& desc) {
	m_fields.insert(std::make_pair(bitOffset, new Field(this, name, type, bitOffset, bitSize, desc)));
	m_size = getSizeByLastField();
}

bool Structure::removeField(Field* field) {
	removeField(field->m_absBitOffset);
}

bool Structure::removeField(int bitOffset) {
	auto it = getFieldIterator(bitOffset);
	if (it != m_fields.end()) {
		m_fields.erase(it);
		return true;
	}
	return false;
}

bool Structure::moveField(int bitOffset, int bitsCount) {
	auto it = getFieldIterator(bitOffset);
	if (it == m_fields.end())
		return false;
	auto field = it->second;

	if (bitsCount > 0) {
		if (!areEmptyFields(field->m_absBitOffset + field->getBitSize(), std::abs(bitsCount)))
			return false;
	}
	else {
		if (!areEmptyFields(field->m_absBitOffset - std::abs(bitsCount), std::abs(bitsCount)))
			return false;
	}

	moveField_(field->m_absBitOffset, bitsCount);
	field->m_absBitOffset += bitsCount;
	return true;
}

bool Structure::moveFields(int bitOffset, int bitsCount) {
	int firstBitOffset = bitOffset;
	int lastBitOffset = m_size * 0x8 - 1;
	if (!areEmptyFields((bitsCount > 0 ? lastBitOffset : firstBitOffset) - std::abs(bitsCount), std::abs(bitsCount)))
		return false;

	auto it = getFieldIterator(firstBitOffset);
	auto end = m_fields.end();
	if (bitsCount > 0) {
		end--;
		it--;
		std::swap(it, end);
	}
	while (it != end) {
		auto field = it->second;
		moveField_(field->m_absBitOffset, bitsCount);
		field->m_absBitOffset += bitsCount;
		if (bitsCount > 0)
			it--; else it++;
	}
	return true;
}

Structure::FieldMapType::iterator Structure::getFieldIterator(int bitOffset) {
	auto it = std::prev(m_fields.upper_bound(bitOffset));
	if (it != m_fields.end()) {
		auto field = it->second;
		if (bitOffset >= field->m_absBitOffset && bitOffset < field->m_absBitOffset + field->getBitSize()) {
			return it;
		}
	}
	return m_fields.end();
}

Structure::Field* Structure::getDefaultField() {
	return m_defaultField;
}

void Structure::moveField_(int bitOffset, int bitsCount) {
	auto field_ = m_fields.extract(bitOffset);
	field_.key() += bitsCount;
	m_fields.insert(std::move(field_));
}
