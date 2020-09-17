#include "MemLocation.h"

using namespace CE::Decompiler;

bool MemLocation::intersect(const MemLocation& location) const {
	if (m_type == ALL || location.m_type == ALL)
		return true;
	if (m_type != location.m_type)
		return false;
	if (m_baseAddrHash != location.m_baseAddrHash)
		return false;
	auto Size1 = getLocSize();
	auto Size2 = location.getLocSize();
	auto C = (location.m_offset - m_offset) + Size2;
	auto minBoundary = -C;
	auto maxBoundary = minBoundary + (Size1 + Size2);
	auto Delta = 0;
	return Delta >= minBoundary && Delta < maxBoundary;
}

bool MemLocation::equal(const MemLocation& location) const {
	if (!m_arrDims.empty() || !location.m_arrDims.empty())
		return false;
	return (m_type == location.m_type && m_type != ALL)
		&& m_baseAddrHash == location.m_baseAddrHash
		&& m_offset == location.m_offset
		&& m_valueSize == location.m_valueSize;
}

int MemLocation::getLocSize() const {
	int result = m_valueSize;
	for (auto arrDims : m_arrDims) {
		if (arrDims.m_itemsMaxCount == -1) {
			return 10000000;
		}
		result += arrDims.m_itemSize * arrDims.m_itemsMaxCount;
	}
	return result;
}