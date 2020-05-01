#pragma once
#include <main.h>


namespace DB
{
	using Id = int;

	class AbstractMapper;
	class DomainObject
	{
	public:
		AbstractMapper* m_mapper = nullptr;

		DomainObject(Id id = 0)
			: m_id(id)
		{}

		virtual ~DomainObject() {

		}

		Id getId() {
			return m_id;
		}

		void setId(Id id) {
			m_id = id;
		}
	private:
		Id m_id;
	};
};