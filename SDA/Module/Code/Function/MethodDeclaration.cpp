#include "MethodDeclaration.h"
#include "../Type/Class.h"
#include <Manager/FunctionDeclManager.h>

//using namespace CE::Function;

CE::Function::MethodDecl::MethodDecl(FunctionDeclManager* manager, DataType::Class* Class, DataType::Signature* signature, std::string name, std::string desc)
	: m_class(Class), FunctionDecl(manager, signature, name, desc)
{}

CE::Function::MethodDecl::MethodDecl(FunctionDeclManager* manager, DataType::Signature* signature, std::string name, std::string desc)
	: MethodDecl(manager, nullptr, signature, name, desc)
{}

void CE::Function::MethodDecl::setClass(DataType::Class* Class)
{
	auto typeUnit = DataType::GetUnit(Class, "*");
	if (getSignature()->getArgList().size() > 0) {
		getSignature()->setArgumentType(0, typeUnit);
	}
	else {
		getSignature()->addArgument("this", typeUnit);
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
