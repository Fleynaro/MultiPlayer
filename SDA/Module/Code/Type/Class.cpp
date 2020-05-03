#include "Class.h"

using namespace CE;
using namespace CE::DataType;

Class::Field::Field(const std::string& name, Type* type, std::string desc)
	: m_name(name), m_desc(desc)
{
	setType(type);
}

Class::Field::~Field() {
	m_type->free();
}

std::string& Class::Field::getName() {
	return m_name;
}

void Class::Field::setName(const std::string& name) {
	m_name = name;
}

std::string& Class::Field::getDesc() {
	return m_desc;
}

void Class::Field::setType(Type* type) {
	if (m_type != nullptr)
		m_type->free();
	m_type = type;
	m_type->addOwner();
}

Type* Class::Field::getType() {
	return m_type;
}

Class::Class(TypeManager* typeManager, std::string name, std::string desc)
	: UserType(typeManager, name, desc)
{}

Class::~Class() {
	for (auto it : m_fields)
		delete it.second;
}

bool Class::iterateFields(const std::function<bool(Class*, int&, Field*)>& callback, bool emptyFields)
{
	if (getBaseClass() != nullptr) {
		if (!getBaseClass()->iterateFields(callback, emptyFields))
			return false;
	}

	return iterateFields([&](int& relOffset, Field* field) {
		return callback(this, relOffset, field);
		}, emptyFields);
}

Class::Group Class::getGroup() {
	return Group::Class;
}

int Class::getSize() {
	return getSizeWithoutVTable() + hasVTable() * 0x8;
}

int Class::getSizeWithoutVTable() {
	int result = 0;
	if (getBaseClass() != nullptr) {
		result += getBaseClass()->getSizeWithoutVTable();
	}
	return result + getRelSize();
}

int Class::getRelSize() {
	return m_size;
}

void Class::resize(int size) {
	m_size = size;
}

Class::MethodList& Class::getMethodList() {
	return m_methods;
}

Class::FieldDict& Class::getFieldDict() {
	return m_fields;
}

void Class::addMethod(Function::MethodDecl* method) {
	getMethodList().push_back(method);
	method->setClass(this);
}

int Class::getAllMethodCount() {
	return static_cast<int>(getMethodList().size()) +
		(getBaseClass() != nullptr ? getBaseClass()->getAllMethodCount() : 0);
}

int Class::getAllFieldCount() {
	return static_cast<int>(getFieldDict().size()) +
		(getBaseClass() != nullptr ? getBaseClass()->getAllFieldCount() : 0);
}

int Class::getBaseOffset() {
	return getBaseClass() != nullptr ? getBaseClass()->getRelSize() + getBaseClass()->getBaseOffset() : 0;
}

bool Class::iterateClasses(std::function<bool(Class*)> callback)
{
	if (getBaseClass() != nullptr) {
		if (!getBaseClass()->iterateClasses(callback))
			return false;
	}

	return callback(this);
}

bool Class::iterateAllMethods(std::function<bool(Function::MethodDecl*)> callback)
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

bool Class::iterateMethods(std::function<bool(Function::MethodDecl*)> callback)
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

bool Class::iterateFields(const std::function<bool(int&, Field*)>& callback, bool emptyFields)
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

bool Class::iterateFieldsWithOffset(std::function<bool(Class*, int, Field*)> callback, bool emptyFields)
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

Class* Class::getBaseClass() {
	return m_base;
}

void Class::setBaseClass(Class* base) {
	m_base = base;
}

CE::Function::VTable* Class::getVtable() {
	if (m_vtable != nullptr && getBaseClass() != nullptr) {
		return getBaseClass()->getVtable();
	}
	return m_vtable;
}

bool Class::hasVTable() {
	return getVtable() != nullptr;
}

void Class::setVtable(Function::VTable* vtable) {
	m_vtable = vtable;
}

int Class::getSizeByLastField() {
	if (m_fields.size() == 0)
		return 0;
	auto lastField = --m_fields.end();
	return lastField->first + lastField->second->getType()->getSize();
}

std::pair<Class*, int> Class::getFieldLocationByOffset(int offset) {
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

int Class::getNextEmptyBytesCount(int startByteIdx) {
	auto it = m_fields.upper_bound(startByteIdx);
	if (it != m_fields.end()) {
		return it->first - startByteIdx;
	}
	return m_size - startByteIdx;
}

bool Class::areEmptyFields(int startByteIdx, int size) {
	if (startByteIdx < 0 || size <= 0)
		return false;

	if (getNextEmptyBytesCount(startByteIdx) < size)
		return false;

	return getFieldIterator(startByteIdx) == m_fields.end();
}

Class::Field* Class::getDefaultField() {
	static Field defaultField = Field("undefined", new Byte);
	return &defaultField;
}

bool Class::isDefaultField(Field* field) {
	return field == getDefaultField();
}

std::pair<int, Class::Field*> Class::getField(int relOffset) {
	auto it = getFieldIterator(relOffset);
	if (it != m_fields.end()) {
		return std::make_pair(it->first, it->second);
	}
	return std::make_pair(-1, getDefaultField());
}

Class::FieldDict::iterator Class::getFieldIterator(int relOffset) {
	auto it = m_fields.lower_bound(relOffset);
	if (it != m_fields.end()) {
		if (it->first <= relOffset && it->first + it->second->getType()->getSize() > relOffset) {
			return it;
		}
	}
	return m_fields.end();
}

void Class::moveField_(int relOffset, int bytesCount) {
	auto field_ = m_fields.extract(relOffset);
	field_.key() += bytesCount;
	m_fields.insert(std::move(field_));
}

bool Class::moveField(int relOffset, int bytesCount) {
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

bool Class::moveFields(int relOffset, int bytesCount) {
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

void Class::addField(int relOffset, std::string name, Type* type, const std::string& desc) {
	m_fields.insert(std::make_pair(relOffset, new Field(name, type, desc)));
	m_size = max(m_size, relOffset + type->getSize());
}

bool Class::removeField(int relOffset) {
	auto it = getFieldIterator(relOffset);
	if (it != m_fields.end()) {
		delete it->second;
		m_fields.erase(it);
		return true;
	}
	return false;
}
