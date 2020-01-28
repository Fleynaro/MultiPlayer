#include "Method.h"
#include "../Type/Class.h"

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

/*CE::Function::Method* CE::Function::Function::getMethodBasedOn() {
	auto method = new Method(m_addr, m_ranges, getId(), getName(), getDesc());
	method->getArgNameList().swap(getArgNameList());
	method->getSignature().getArgList().swap(getSignature().getArgList());
	method->getSignature().setReturnType(getSignature().getReturnType());
	return method;
}*/