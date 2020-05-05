#include "Class.h"

using namespace CE;
using namespace CE::DataType;

Class::Class(TypeManager* typeManager, const std::string& name, const std::string& desc)
	: Structure(typeManager, name, desc)
{}

Type::Group Class::getGroup() {
	return Group::Class;
}

Class::MethodListType& CE::DataType::Class::getMethods() {
	return m_methods;
}

void Class::addMethod(Function::MethodDecl* method) {
	getMethods().push_back(method);
	method->setClass(this);
}

std::list<Class*> Class::getClassesInHierarchy() {
	if (m_base != nullptr) {
		auto result = getClassesInHierarchy();
		result.push_back(this);
		return result;
	}
	return { this };
}

Class* Class::getBaseClass() {
	return m_base;
}

void Class::setBaseClass(Class* base, bool createBaseClassField) {
	m_base = base;

	if (createBaseClassField) {
		int baseClassOffset = 0x0;
		if (m_vtable != nullptr) {
			if (m_base != nullptr && m_base->m_vtable == nullptr) {
				baseClassOffset = 0x8;
			}
		}
		
		auto oldSize = getSize();
		if (oldSize < base->getSize()) {
			resize(base->getSize());
		}
		if (!areEmptyFields(baseClassOffset, base->getSize())) {
			resize(oldSize);
			throw std::exception("set base class");
		}

		addField(baseClassOffset, "base", GetUnit(base), "{this field created automatically}");
	}
}

CE::Function::VTable* Class::getVtable() {
	if (m_vtable != nullptr && getBaseClass() != nullptr) {
		return getBaseClass()->getVtable();
	}
	return m_vtable;
}

void Class::setVtable(Function::VTable* vtable) {
	m_vtable = vtable;
}

