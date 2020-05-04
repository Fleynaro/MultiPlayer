#include "MethodDeclaration.h"
#include "../Type/Class.h"
#include <Manager/FunctionDeclManager.h>

//using namespace CE::Function;

CE::Function::MethodDecl::MethodDecl(FunctionDeclManager* manager, DataType::Class* Class, std::string name, std::string desc)
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

void CE::Function::MethodDecl::setClass(DataType::Class* Class)
{
	auto typeUnit = DataType::GetUnit(Class, "*");
	if (getSignature().getArgList().size() > 0) {
		getSignature().setArgument(0, typeUnit);
	}
	else {
		addArgument(typeUnit, "this");
	}
}

CE::DataType::Class* CE::Function::MethodDecl::getClass() {
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
