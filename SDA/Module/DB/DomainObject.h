#pragma once
#include <main.h>


namespace DB
{
	using Id = int;

	class IMapper;
	class IDomainObject
	{
	public:
		virtual ~IDomainObject() {}
		virtual Id getId() = 0;
		virtual void setId(Id id) {}
		virtual IMapper* getMapper() { return nullptr; }
		virtual void setMapper(IMapper* mapper) {}
	};

	class DomainObject : public IDomainObject
	{
	public:
		DomainObject(Id id = 0)
			: m_id(id)
		{}

		Id getId() override {
			return m_id;
		}

		void setId(Id id) override {
			m_id = id;
		}

		IMapper* getMapper() override {
			return m_mapper;
		}

		void setMapper(IMapper* mapper) override {
			m_mapper = mapper;
		}
	private:
		Id m_id;
		IMapper* m_mapper = nullptr;
	};
};