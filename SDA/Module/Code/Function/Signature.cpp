#include "Signature.h"
#include "GUI/Windows/ItemLists/FunctionTagList.h"

void GUI::Units::FuncInfo::buildDescription() {
	addItem(m_tagShortCut = new GUI::Widget::FunctionTagShortCut(m_function));
	DeclInfo::buildDescription();
}

CE::Function::Signature::~Signature() {
	if (m_returnType != nullptr)
		m_returnType->free();
}

void CE::Function::Signature::setReturnType(Type::Type* returnType) {
	if (m_returnType != nullptr)
		m_returnType->free();
	m_returnType = returnType;
	m_returnType->addOwner();
	//m_retTypeChanged = true;
}

Type::Type* CE::Function::Signature::getReturnType() {
	return m_returnType;
}

CE::Function::Signature::ArgTypeList& CE::Function::Signature::getArgList() {
	return m_args;
}

void CE::Function::Signature::addArgument(Type::Type* type) {
	type->addOwner();
	m_args.push_back(type);
}

void CE::Function::Signature::changeArgument(int id, Type::Type* type) {
	m_args[id]->free();
	type->addOwner();
	m_args[id] = type;
}

void CE::Function::Signature::removeLastArgument() {
	if (m_args.size() > 0)
		m_args[m_args.size() - 1]->free();
	m_args.pop_back();
}

void CE::Function::Signature::deleteAllArguments() {
	for (auto it : m_args) {
		it->free();
	}
	m_args.clear();
}
