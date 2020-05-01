#include "Class.h"

CE::Type::Class::Field::Field(const std::string& name, Type* type, std::string desc)
	: m_name(name), m_desc(desc)
{
	setType(type);
}

CE::Type::Class::Field::~Field() {
	m_type->free();
}

std::string& CE::Type::Class::Field::getName() {
	return m_name;
}

void CE::Type::Class::Field::setName(const std::string& name) {
	m_name = name;
}

std::string& CE::Type::Class::Field::getDesc() {
	return m_desc;
}

void CE::Type::Class::Field::setType(Type* type) {
	if (m_type != nullptr)
		m_type->free();
	m_type = type;
	m_type->addOwner();
}

CE::Type::Type* CE::Type::Class::Field::getType() {
	return m_type;
}

CE::Type::Class::Class(int id, std::string name, std::string desc)
	: UserType(id, name, desc)
{}

CE::Type::Class::~Class() {
	for (auto it : m_fields)
		delete it.second;
}

bool CE::Type::Class::iterateFields(const std::function<bool(Class*, int&, Field*)>& callback, bool emptyFields)
{
	if (getBaseClass() != nullptr) {
		if (!getBaseClass()->iterateFields(callback, emptyFields))
			return false;
	}

	return iterateFields([&](int& relOffset, Field* field) {
		return callback(this, relOffset, field);
		}, emptyFields);
}

CE::Type::Class::Group CE::Type::Class::getGroup() {
	return Group::Class;
}

int CE::Type::Class::getSize() {
	return getSizeWithoutVTable() + hasVTable() * 0x8;
}

int CE::Type::Class::getSizeWithoutVTable() {
	int result = 0;
	if (getBaseClass() != nullptr) {
		result += getBaseClass()->getSizeWithoutVTable();
	}
	return result + getRelSize();
}

int CE::Type::Class::getRelSize() {
	return m_size;
}

void CE::Type::Class::resize(int size) {
	m_size = size;
}

CE::Type::Class::MethodList& CE::Type::Class::getMethodList() {
	return m_methods;
}

CE::Type::Class::FieldDict& CE::Type::Class::getFieldDict() {
	return m_fields;
}

void CE::Type::Class::addMethod(Function::MethodDecl* method) {
	getMethodList().push_back(method);
	method->setClass(this);
}

int CE::Type::Class::getAllMethodCount() {
	return static_cast<int>(getMethodList().size()) +
		(getBaseClass() != nullptr ? getBaseClass()->getAllMethodCount() : 0);
}

int CE::Type::Class::getAllFieldCount() {
	return static_cast<int>(getFieldDict().size()) +
		(getBaseClass() != nullptr ? getBaseClass()->getAllFieldCount() : 0);
}

int CE::Type::Class::getBaseOffset() {
	return getBaseClass() != nullptr ? getBaseClass()->getRelSize() + getBaseClass()->getBaseOffset() : 0;
}

bool CE::Type::Class::iterateClasses(std::function<bool(Class*)> callback)
{
	if (getBaseClass() != nullptr) {
		if (!getBaseClass()->iterateClasses(callback))
			return false;
	}

	return callback(this);
}

bool CE::Type::Class::iterateAllMethods(std::function<bool(Function::MethodDecl*)> callback)
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

bool CE::Type::Class::iterateMethods(std::function<bool(Function::MethodDecl*)> callback)
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

bool CE::Type::Class::iterateFields(const std::function<bool(int&, Field*)>& callback, bool emptyFields)
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

bool CE::Type::Class::iterateFieldsWithOffset(std::function<bool(Class*, int, Field*)> callback, bool emptyFields)
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

CE::Type::Class* CE::Type::Class::getBaseClass() {
	return m_base;
}

void CE::Type::Class::setBaseClass(Class* base) {
	m_base = base;
}

CE::Function::VTable* CE::Type::Class::getVtable() {
	if (m_vtable != nullptr && getBaseClass() != nullptr) {
		return getBaseClass()->getVtable();
	}
	return m_vtable;
}

bool CE::Type::Class::hasVTable() {
	return getVtable() != nullptr;
}

void CE::Type::Class::setVtable(Function::VTable* vtable) {
	m_vtable = vtable;
}

int CE::Type::Class::getSizeByLastField() {
	if (m_fields.size() == 0)
		return 0;
	auto lastField = --m_fields.end();
	return lastField->first + lastField->second->getType()->getSize();
}

std::pair<CE::Type::Class*, int> CE::Type::Class::getFieldLocationByOffset(int offset) {
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

int CE::Type::Class::getNextEmptyBytesCount(int startByteIdx) {
	auto it = m_fields.upper_bound(startByteIdx);
	if (it != m_fields.end()) {
		return it->first - startByteIdx;
	}
	return m_size - startByteIdx;
}

bool CE::Type::Class::areEmptyFields(int startByteIdx, int size) {
	if (startByteIdx < 0 || size <= 0)
		return false;

	if (getNextEmptyBytesCount(startByteIdx) < size)
		return false;

	return getFieldIterator(startByteIdx) == m_fields.end();
}

CE::Type::Class::Field* CE::Type::Class::getDefaultField() {
	static Field defaultField = Field("undefined", new Byte);
	return &defaultField;
}

bool CE::Type::Class::isDefaultField(Field* field) {
	return field == getDefaultField();
}

std::pair<int, CE::Type::Class::Field*> CE::Type::Class::getField(int relOffset) {
	auto it = getFieldIterator(relOffset);
	if (it != m_fields.end()) {
		return std::make_pair(it->first, it->second);
	}
	return std::make_pair(-1, getDefaultField());
}

CE::Type::Class::FieldDict::iterator CE::Type::Class::getFieldIterator(int relOffset) {
	auto it = m_fields.lower_bound(relOffset);
	if (it != m_fields.end()) {
		if (it->first <= relOffset && it->first + it->second->getType()->getSize() > relOffset) {
			return it;
		}
	}
	return m_fields.end();
}

void CE::Type::Class::moveField_(int relOffset, int bytesCount) {
	auto field_ = m_fields.extract(relOffset);
	field_.key() += bytesCount;
	m_fields.insert(std::move(field_));
}

bool CE::Type::Class::moveField(int relOffset, int bytesCount) {
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

bool CE::Type::Class::moveFields(int relOffset, int bytesCount) {
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

void CE::Type::Class::addField(int relOffset, std::string name, Type* type, const std::string& desc) {
	m_fields.insert(std::make_pair(relOffset, new Field(name, type, desc)));
	m_size = max(m_size, relOffset + type->getSize());
}

bool CE::Type::Class::removeField(int relOffset) {
	auto it = getFieldIterator(relOffset);
	if (it != m_fields.end()) {
		delete it->second;
		m_fields.erase(it);
		return true;
	}
	return false;
}
