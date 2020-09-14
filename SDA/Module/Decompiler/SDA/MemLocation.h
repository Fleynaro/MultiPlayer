#pragma once
#include <main.h>
#include <Utils/ObjectHash.h>

namespace CE::Decompiler
{
	struct MemLocation {
		enum LOCATION_TYPE {
			STACK,
			GLOBAL,
			IMPLICIT,
			ALL
		};

		struct ArrayDim {
			int m_itemSize;
			int m_itemsMaxCount = -1;
		};

		LOCATION_TYPE m_type;
		ObjectHash::Hash m_baseAddrHash = 0x0;
		int64_t m_offset = 0x0;
		std::list<ArrayDim> m_arrDims;
		int m_valueSize = 0x0;

		bool intersect(const MemLocation& location) const {
			if (m_type == ALL || location.m_type == ALL)
				return true;
			if (m_type != location.m_type)
				return false;
			if (m_baseAddrHash != location.m_baseAddrHash)
				return false;
			auto Size1 = getLocSize();
			auto Size2 = getLocSize();
			auto C = (m_offset - location.m_offset) + Size1;
			auto minBoundary = -C;
			auto maxBoundary = minBoundary + (Size1 + Size2);
			auto Delta = 0;
			return Delta >= minBoundary && Delta <= maxBoundary;
		}

		bool equal(const MemLocation& location) const {
			if (m_arrDims.empty() || location.m_arrDims.empty())
				return false;
			return (m_type == location.m_type && m_type != ALL)
				&& m_baseAddrHash == location.m_baseAddrHash
				&& m_offset == location.m_offset
				&& m_valueSize == location.m_valueSize;
		}

		static MemLocation ALL() {
			MemLocation memLoc;
			memLoc.m_type = ALL;
			return memLoc;
		}
	private:
		int getLocSize() const {
			int result = m_valueSize;
			for (auto arrDims : m_arrDims) {
				if (arrDims.m_itemsMaxCount == -1) {
					return 10000000;
				}
				result += arrDims.m_itemSize * arrDims.m_itemsMaxCount;
			}
			return result;
		}
	};
};