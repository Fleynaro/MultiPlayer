#include "DomainObject.h"

DB::DomainObject::DomainObject(Id id)
	: m_id(id)
{}

DB::Id DB::DomainObject::getId() {
	return m_id;
}

void DB::DomainObject::setId(Id id) {
	m_id = id;
}

DB::IMapper* DB::DomainObject::getMapper() {
	return m_mapper;
}

void DB::DomainObject::setMapper(IMapper* mapper) {
	m_mapper = mapper;
}
