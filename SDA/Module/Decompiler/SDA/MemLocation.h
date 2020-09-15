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
			int m_itemSize = 0;
			int m_itemsMaxCount = -1;
		};

		LOCATION_TYPE m_type;
		ObjectHash::Hash m_baseAddrHash = 0x0;
		int64_t m_offset = 0x0;
		std::list<ArrayDim> m_arrDims;
		int m_valueSize = 0x0;

		bool intersect(const MemLocation& location) const;

		bool equal(const MemLocation& location) const;
		
		int getLocSize() const;
	};
};