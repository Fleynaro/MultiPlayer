#include "TypeUnit.h"
#include "SystemType.h"
#include "Typedef.h"
#include "Utility/Generic.h"

using namespace CE;
using namespace CE::DataType;

Unit::Unit(DataType::Type* type, std::list<int> levels)
	: Type(type->getTypeManager(), "", ""), m_type(type), m_levels(levels)
{}

Unit::Group Unit::getGroup() {
	return m_type->getGroup();
}

bool Unit::isUserDefined() {
	return m_type->isUserDefined();
}

bool Unit::isFloatingPoint() {
	if (auto sysType = dynamic_cast<SystemType*>(getBaseType(true, false))) {
		return sysType->getSet() == SystemType::Real;
	}
	return false;
}

int Unit::getPointerLvl() {
	return (int)getPointerLevels().size();
}

bool Unit::isPointer() {
	return getPointerLvl() > 0;
}

std::list<int> Unit::getPointerLevels() {
	if (auto Typedef = dynamic_cast<DataType::Typedef*>(m_type)) {
		std::list<int> result = Typedef->getRefType()->getPointerLevels();
		result.insert(result.begin(), m_levels.begin(), m_levels.end());
		return result;
	}
	return m_levels;
}

void Unit::addPointerLevelInFront(int size) {
	m_levels.push_front(size);
}

void Unit::addPointerLevelInBack(int size) {
	m_levels.push_back(size);
}

bool Unit::isString() {
	if (!isPointer())
		return false;
	auto baseType = getBaseType();
	return dynamic_cast<Char*>(baseType) || dynamic_cast<WChar*>(baseType);
}

bool Unit::equal(DataType::Unit* typeUnit) {
	if (getBaseType() != typeUnit->getBaseType())
		return false;
	auto ptrList1 = getPointerLevels();
	auto ptrList2 = typeUnit->getPointerLevels();
	if (ptrList1.size() != ptrList2.size())
		return false;
	auto it1 = ptrList1.begin();
	auto it2 = ptrList2.begin();
	while (it1 != ptrList1.end()) {
		if (*it1 != *it2)
			return false;
		it1++;
		it2++;
	}
	return true;
}

int Unit::getPriority() {
	auto baseType = getBaseType();
	auto size = min(baseType->getSize(), 0x8);
	bool hasPointerLvl = getPointerLvl() != 0;
	bool isSigned = baseType->isSigned();
	bool isNotSimple = baseType->getGroup() != Simple;
	return size | (hasPointerLvl << 3) | (isSigned << 4) | (isNotSimple << 5);
}

const std::string Unit::getName() {
	return m_type->getName();
}

const std::string Unit::getComment() {
	return m_type->getComment();
}

void Unit::setName(const std::string& name)
{
	m_type->setName(name);
}

void Unit::setComment(const std::string& comment)
{
	m_type->setComment(comment);
}

std::string Unit::getDisplayName() {
	auto name = m_type->getDisplayName();
	for (auto level : m_levels) {
		name += (level == 1 ? "*" : ("[" + std::to_string(level) + "]"));
	}
	return name;
}

int Unit::getSize() {
	return getPointerLvl() > 0 ? sizeof(std::uintptr_t) : m_type->getSize();
}

std::string Unit::getViewValue(void* addr) {
	return "(" + getDisplayName() + ")0x" + Generic::String::NumberToHex(*(uint64_t*)addr);
}

DataType::Type* Unit::getType() {
	return m_type;
}

DB::Id Unit::getId() {
	return m_type->getId();
}

void Unit::setId(DB::Id id) {
	return m_type->setId(id);
}

DB::IMapper* Unit::getMapper() {
	return m_type->getMapper();
}

void Unit::setMapper(DB::IMapper* mapper) {
	m_type->setMapper(mapper);
}

/*
	arr					<=>			arr
	arr*				<=>			arr[1]
	arr*[20][5]			<=>			arr[20][5][1]
	(arr[2])*			<=>			arr[1][2]
	(arr**[5])*			<=>			arr[1][5][1][1]
	((arr[5])*[10])*	<=>			arr[1][10][1][5]
*/
std::list<int> CE::DataType::ParsePointerLevelsStr(const std::string& str) {
	std::list<int> result;
	std::list<int> seq;

	int lastClosedSquareBracketIdx = 0;
	int idx = (int)str.length() - 1;
	while (idx >= 0) {
		auto ch = str[idx];

		if (lastClosedSquareBracketIdx != 0) {
			if (ch == '[') {
				auto arrSize = std::stoi(str.substr(idx + 1, lastClosedSquareBracketIdx - idx - 1));
				seq.push_front(arrSize);

				if (idx != 0 && str[idx - 1] == ']') {
					lastClosedSquareBracketIdx = idx - 1;
				}
				else {
					result.insert(result.end(), seq.begin(), seq.end());
					lastClosedSquareBracketIdx = 0;
					seq.clear();
				}
			}
		}
		else {
			if (ch == '*') {
				result.push_back(1);
			}
			else if (ch == ']') {
				lastClosedSquareBracketIdx = idx;
			}
		}

		idx--;
	}

	return result;
}

DataTypePtr CE::DataType::CloneUnit(DataTypePtr dataType) {
	return GetUnit(dataType->getType(), GetPointerLevelStr(dataType));
}

std::string CE::DataType::GetPointerLevelStr(DataTypePtr type) {
	std::string result = "";
	for (auto arrSize : type->getPointerLevels()) {
		result = result + "["+ std::to_string(arrSize) +"]";
	}
	return result;
}

DataTypePtr CE::DataType::GetUnit(DataType::Type* type, const std::string& levels) {
	auto levels_list = ParsePointerLevelsStr(levels);
	return std::make_shared<DataType::Unit>(type, levels_list);
}
