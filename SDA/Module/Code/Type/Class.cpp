#include "Class.h"

CE::DataType::Class::Field::Field(const std::string& name, Type* type, std::string desc)
	: m_name(name), m_desc(desc)
{
	setType(type);
}

CE::DataType::Class::Field::~Field() {
	m_type->free();
}

std::string& CE::DataType::Class::Field::getName() {
	return m_name;
}

void CE::DataType::Class::Field::setName(const std::string& name) {
	m_name = name;
}

std::string& CE::DataType::Class::Field::getDesc() {
	return m_desc;
}

void CE::DataType::Class::Field::setType(Type* type) {
	if (m_type != nullptr)
		m_type->free();
	m_type = type;
	m_type->addOwner();
}

CE::DataType::Type* CE::DataType::Class::Field::getType() {
	return m_type;
}

CE::DataType::Class::Class(int id, std::string name, std::string desc)
	: UserType(id, name, desc)
{}

CE::DataType::Class::~Class() {
	for (auto it : m_fields)
		delete it.second;
}

bool CE::DataType::Class::iterateFields(const std::function<bool(Class*, int&, Field*)>& callback, bool emptyFields)
{
	if (getBaseClass() != nullptr) {
		if (!getBaseClass()->iterateFields(callback, emptyFields))
			return false;
	}

	return iterateFields([&](int& relOffset, Field* field) {
		return callback(this, relOffset, field);
		}, emptyFields);
}

CE::DataType::Class::Group CE::DataType::Class::getGroup() {
	return Group::Class;
}

int CE::DataType::Class::getSize() {
	return getSizeWithoutVTable() + hasVTable() * 0x8;
}

int CE::DataType::Class::getSizeWithoutVTable() {
	int result = 0;
	if (getBaseClass() != nullptr) {
		result += getBaseClass()->getSizeWithoutVTable();
	}
	return result + getRelSize();
}

int CE::DataType::Class::getRelSize() {
	return m_size;
}

void CE::DataType::Class::resize(int size) {
	m_size = size;
}

CE::DataType::Class::MethodList& CE::DataType::Class::getMethodList() {
	return m_methods;
}

CE::DataType::Class::FieldDict& CE::DataType::Class::getFieldDict() {
	return m_fields;
}

void CE::DataType::Class::addMethod(Function::MethodDecl* method) {
	getMethodList().push_back(method);
	method->setClass(this);
}

int CE::DataType::Class::getAllMethodCount() {
	return static_cast<int>(getMethodList().size()) +
		(getBaseClass() != nullptr ? getBaseClass()->getAllMethodCount() : 0);
}

int CE::DataType::Class::getAllFieldCount() {
	return static_cast<int>(getFieldDict().size()) +
		(getBaseClass() != nullptr ? getBaseClass()->getAllFieldCount() : 0);
}

int CE::DataType::Class::getBaseOffset() {
	return getBaseClass() != nullptr ? getBaseClass()->getRelSize() + getBaseClass()->getBaseOffset() : 0;
}

bool CE::DataType::Class::iterateClasses(std::function<bool(Class*)> callback)
{
	if (getBaseClass() != nullptr) {
		if (!getBaseClass()->iterateClasses(callback))
			return false;
	}

	return callback(this);
}

bool CE::DataType::Class::iterateAllMethods(std::function<bool(Function::MethodDecl*)> callback)
{
	if (getBaseClass() != nullptr) {
		if (!getBaseClass()->iterateAllMethods(callback))
			return false;
	}

	for (auto method : getMethodList()) {
		if (!callback(method))
			return false;
	}
	return true;
}

bool CE::DataType::Class::iterateMethods(std::function<bool(Function::MethodDecl*)> callback)
{
	std::set<std::string> methods;
	return iterateAllMethods([&](Function::MethodDecl* method) {
		std::string sigName = method->getSigName();
		if (!methods.count(sigName)) {
			return callback(method);
		}
		methods.insert(sigName);
		return true;
		});
}

bool CE::DataType::Class::iterateFields(const std::function<bool(int&, Field*)>& callback, bool emptyFields)
{
	if (!emptyFields) {
		for (auto& it : m_fields) {
			int relOffset = it.first;
			if (!callback(relOffset, it.second))
				return false;
		}
	}
	else {
		for (int byteIdx = 0; byteIdx < getRelSize(); byteIdx++) {
			auto fieldPair = getField(byteIdx);

			if (!callback(byteIdx, fieldPair.second))
				return false;

			if (fieldPair.first != -1) {
				byteIdx += fieldPair.second->getType()->getSize() - 1;
			}
		}
	}

	return true;
}

bool CE::DataType::Class::iterateFieldsWithOffset(std::function<bool(Class*, int, Field*)> callback, bool emptyFields)
{
	int curClassBase = hasVTable() * 0x8;
	Class* curClass = nullptr;
	return iterateFields([&](Class* Class, int& relOffset, Field* field) {
		if (curClass != nullptr && curClass != Class) {
			curClassBase += curClass->getRelSize();
		}
		int curOffset = curClassBase + relOffset;
		return callback(Class, curOffset, field);
		}, emptyFields);
}

CE::DataType::Class* CE::DataType::Class::getBaseClass() {
	return m_base;
}

void CE::DataType::Class::setBaseClass(Class* base) {
	m_base = base;
}

CE::Function::VTable* CE::DataType::Class::getVtable() {
	if (m_vtable != nullptr && getBaseClass() != nullptr) {
		return getBaseClass()->getVtable();
	}
	return m_vtable;
}

bool CE::DataType::Class::hasVTable() {
	return getVtable() != nullptr;
}

void CE::DataType::Class::setVtable(Function::VTable* vtable) {
	m_vtable = vtable;
}

int CE::DataType::Class::getSizeByLastField() {
	if (m_fields.size() == 0)
		return 0;
	auto lastField = --m_fields.end();
	return lastField->first + lastField->second->getType()->getSize();
}

std::pair<CE::DataType::Class*, int> CE::DataType::Class::getFieldLocationByOffset(int offset) {
	std::pair<Class*, int> result(nullptr, -1);
	int curOffset = hasVTable() * 0x8;
	iterateClasses([&](Class* Class) {
		if (curOffset + Class->getRelSize() > offset) {
			if (result.second == -1) {
				result.first = Class;
				result.second = offset - curOffset;
			}
		}
		curOffset += Class->getRelSize();
		return true;
		});
	return result;
}

int CE::DataType::Class::getNextEmptyBytesCount(int startByteIdx) {
	auto it = m_fields.upper_bound(startByteIdx);
	if (it != m_fields.end()) {
		return it->first - startByteIdx;
	}
	return m_size - startByteIdx;
}

bool CE::DataType::Class::areEmptyFields(int startByteIdx, int size) {
	if (startByteIdx < 0 || size <= 0)
		return false;

	if (getNextEmptyBytesCount(startByteIdx) < size)
		return false;

	return getFieldIterator(startByteIdx) == m_fields.end();
}

CE::DataType::Class::Field* CE::DataType::Class::getDefaultField() {
	static Field defaultField = Field("undefined", new Byte);
	return &defaultField;
}

bool CE::DataType::Class::isDefaultField(Field* field) {
	return field == getDefaultField();
}

std::pair<int, CE::DataType::Class::Field*> CE::DataType::Class::getField(int relOffset) {
	auto it = getFieldIterator(relOffset);
	if (it != m_fields.end()) {
		return std::make_pair(it->first, it->second);
	}
	return std::make_pair(-1, getDefaultField());
}

CE::DataType::Class::FieldDict::iterator CE::DataType::Class::getFieldIterator(int relOffset) {
	auto it = m_fields.lower_bound(relOffset);
	if (it != m_fields.end()) {
		if (it->first <= relOffset && it->first + it->second->getType()->getSize() > relOffset) {
			return it;
		}
	}
	return m_fields.end();
}

void CE::DataType::Class::moveField_(int relOffset, int bytesCount) {
	auto field_ = m_fields.extract(relOffset);
	field_.key() += bytesCount;
	m_fields.insert(std::move(field_));
}

bool CE::DataType::Class::moveField(int relOffset, int bytesCount) {
	auto field = getFieldIterator(relOffset);
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

	moveField_(relOffset, bytesCount);
	return true;
}

bool CE::DataType::Class::moveFields(int relOffset, int bytesCount) {
	int firstOffset = relOffset;
	int lastOffset = m_size - 1;
	if (!areEmptyFields((bytesCount > 0 ? lastOffset : firstOffset) - std::abs(bytesCount), std::abs(bytesCount)))
		return false;

	FieldDict::iterator it = getFieldIterator(firstOffset);
	FieldDict::iterator end = m_fields.end();
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

void CE::DataType::Class::addField(int relOffset, std::string name, Type* type, const std::string& desc) {
	m_fields.insert(std::make_pair(relOffset, new Field(name, type, desc)));
	m_size = max(m_size, relOffset + type->getSize());
}

bool CE::DataType::Class::removeField(int relOffset) {
	auto it = getFieldIterator(relOffset);
	if (it != m_fields.end()) {
		delete it->second;
		m_fields.erase(it);
		return true;
	}
	return false;
}
