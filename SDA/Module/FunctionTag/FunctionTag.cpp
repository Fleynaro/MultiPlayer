#include "FunctionTag.h"

using namespace CE;
using namespace CE::Function::Tag;

UserTag::UserTag(Tag* parent, const std::string& name, const std::string& comment)
	: Tag(parent, name, comment)
{}

UserTag::UserTag(Function* function, Tag* parent, const std::string& name, const std::string& comment)
	: m_function(function), Tag(parent, name, comment)
{}

void UserTag::setParent(Tag* parent) {
	m_parent = parent;
}

Tag::Type UserTag::getType() {
	return getParent()->getType();
}

bool UserTag::isDefinedForFunc() {
	return getFunction() != nullptr;
}

void UserTag::setFunction(Function* func) {
	m_function = func;
}

Function::Function* UserTag::getFunction() {
	return m_function;
}

SetTag::SetTag()
	: Tag(nullptr, "Set tag", "")
{
	setId(2);
}

Tag::Type SetTag::getType() {
	return SET;
}

GetTag::GetTag()
	: Tag(nullptr, "Get tag", "")
{
	setId(1);
}

Tag::Type GetTag::getType() {
	return GET;
}

Tag::Tag(Tag* parent, const std::string& name, const std::string& comment)
	: m_parent(parent), Descrtiption(name, comment)
{}

bool Tag::isUser() {
	return getParent() != nullptr;
}

Tag* Tag::getParent() {
	return m_parent;
}

