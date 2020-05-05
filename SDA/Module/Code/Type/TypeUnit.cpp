#include "TypeUnit.h"
#include "Typedef.h"
#include "Utility/Generic.h"

using namespace CE;
using namespace CE::DataType;

Unit::Unit(DataType::Type* type, std::vector<int> levels)
	: Type(type->getTypeManager()), m_type(type), m_levels(levels)
{}

Unit::Group Unit::getGroup() {
	return m_type->getGroup();
}

bool Unit::isUserDefined() {
	return m_type->isUserDefined();
}

bool Unit::isPointer() {
	return getPointerLvl() > 0;
}

int Unit::getPointerLvl() {
	return (int)m_levels.size();
}

std::vector<int> Unit::getPointerLevels() {
	if (auto Typedef = dynamic_cast<DataType::Typedef*>(m_type)) {
		std::vector<int> result = Typedef->getRefType()->getPointerLevels();
		result.insert(result.begin(), m_levels.begin(), m_levels.end());
		return result;
	}
	return m_levels;
}

std::string Unit::getName() {
	return m_type->getName();
}

std::string Unit::getDesc() {
	return m_type->getDesc();
}

std::string Unit::getDisplayName() {
	return m_type->getDisplayName() + "*";
}

int Unit::getSize() {
	return isPointer() ? sizeof(std::uintptr_t) : m_type->getSize();
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
std::vector<int> CE::DataType::ParsePointerLevelsStr(const std::string& str) {
	std::vector<int> result;
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
