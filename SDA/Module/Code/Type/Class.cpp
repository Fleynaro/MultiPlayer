#include "Class.h"

using namespace CE;
using namespace CE::DataType;

Class::Class(TypeManager* typeManager, const std::string& name, const std::string& comment)
	: Structure(typeManager, name, comment)
{}

Type::Group Class::getGroup() {
	return Group::Class;
}

Class::MethodListType& CE::DataType::Class::getMethods() {
	return m_methods;
}

void Class::addMethod(Function::Function* method) {
	getMethods().push_back(method);
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

Class::MethodIterator::MethodIterator(Class* Class)
	: m_vtable(Class->getVtable())
{
	m_classes = Class->getClassesInHierarchy();
	updateIterator();
}

bool Class::MethodIterator::hasNext() {
	if (!(m_classes.size() != 0 && m_iterator != m_end))
		return false;
	if (m_signatures.count((*m_iterator)->getSignature()->getSigName()) != 0) {
		next();
		return hasNext();
	}
	return true;
}

Function::Function* Class::MethodIterator::next() {
	//vtable...

	if (m_iterator == m_end) {
		m_classes.pop_front();
		updateIterator();
	}

	auto method = *m_iterator;
	m_iterator++;
	m_signatures.insert(method->getSignature()->getSigName());
	return method;
}

void Class::MethodIterator::updateIterator() {
	m_iterator = m_classes.front()->getMethods().begin();
	m_end = m_classes.front()->getMethods().begin();
}
