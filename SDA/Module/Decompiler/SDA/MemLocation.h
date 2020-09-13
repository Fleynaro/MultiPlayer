#pragma once
#include <main.h>
#include <Utils/ObjectHash.h>

namespace CE::Decompiler
{
	struct Location {
		enum LOCATION_TYPE {
			STACK,
			GLOBAL,
			IMPLICIT
		};

		struct ArrayDim {
			int m_itemSize;
			int m_itemsCount;
		};

		LOCATION_TYPE m_type;
		ObjectHash::Hash m_baseAddrHash = 0x0;
		int64_t m_offset = 0x0;
		std::list<ArrayDim> m_arrDims;
		int m_valueSize = 0x0;

		bool intersect(const Location& location) {
			if (m_type != location.m_type)
				return false;
			if (m_baseAddrHash != location.m_baseAddrHash)
				return false;
			return !(m_offset + m_locSize <= location.m_offset || location.m_offset + location.m_locSize <= m_offset);
		}

		bool equal(const Location& location) {
			return m_type == location.m_type
				&& m_baseAddrHash == location.m_baseAddrHash
				&& m_offset == location.m_offset
				&& m_locSize == location.m_locSize;
		}
	};
};