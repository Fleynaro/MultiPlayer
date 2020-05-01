#include "MethodDeclaration.h"
#include "../Type/Class.h"

//using namespace CE::Function;

CE::Function::MethodDecl::MethodDecl(FunctionDeclManager* manager, Type::Class* Class, std::string name, std::string desc)
	: m_class(Class), FunctionDecl(manager, name, desc)
{}

CE::Function::MethodDecl::MethodDecl(FunctionDeclManager* manager, std::string name, std::string desc)
	: MethodDecl(manager, nullptr, name, desc)
{}

std::string CE::Function::MethodDecl::getSigName() {
	return (isVirtual() ? "virtual " : "") + FunctionDecl::getSigName();
}

std::string CE::Function::MethodDecl::getName() {
	return getClass()->getName() + "::" + FunctionDecl::getName();
}

void CE::Function::MethodDecl::setClass(Type::Class* Class)
{
	if (getSignature().getArgList().size() > 0) {
		getSignature().getArgList()[0]->free();
		getSignature().getArgList()[0] = new Type::Pointer(Class);
	}
	else {
		addArgument(new Type::Pointer(Class), "this");
	}
}

CE::Type::Class* CE::Function::MethodDecl::getClass() {
	return m_class;
}

CE::Function::FunctionDecl::Role CE::Function::MethodDecl::getRole() {
	return m_role;
}

void CE::Function::MethodDecl::setRole(Role role) {
	m_role = role;
}

bool CE::Function::MethodDecl::isVirtual() {
	return getRole() == Role::VirtualMethod || getRole() == Role::VirtualDestructor;
}
