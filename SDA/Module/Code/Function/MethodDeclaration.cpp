#include "MethodDeclaration.h"
#include "../Type/Class.h"

using namespace CE::Function;

MethodDecl::MethodDecl(FunctionDeclManager* manager, Type::Class* Class, std::string name, std::string desc)
	: m_class(Class), FunctionDecl(manager, name, desc)
{}

MethodDecl::MethodDecl(FunctionDeclManager* manager, std::string name, std::string desc)
	: MethodDecl(manager, nullptr, name, desc)
{}

std::string MethodDecl::getSigName() {
	return (isVirtual() ? "virtual " : "") + FunctionDecl::getSigName();
}

std::string MethodDecl::getName() {
	return getClass()->getName() + "::" + FunctionDecl::getName();
}

void MethodDecl::setClass(Type::Class* Class)
{
	if (getSignature().getArgList().size() > 0) {
		getSignature().getArgList()[0]->free();
		getSignature().getArgList()[0] = new Type::Pointer(Class);
	}
	else {
		addArgument(new Type::Pointer(Class), "this");
	}
}

CE::Type::Class* MethodDecl::getClass() {
	return m_class;
}

FunctionDecl::Role MethodDecl::getRole() {
	return m_role;
}

void MethodDecl::setRole(Role role) {
	m_role = role;
}

bool MethodDecl::isVirtual() {
	return getRole() == Role::VirtualMethod || getRole() == Role::VirtualDestructor;
}
