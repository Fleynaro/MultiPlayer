#include "FunctionTag.h"

using namespace CE;
using namespace CE::Function::Tag;

UserTag::UserTag(Tag* parent, const std::string& name, const std::string& desc)
	: Tag(parent, name, desc)
{}

UserTag::UserTag(Function::FunctionDecl* decl, Tag* parent, const std::string& name, const std::string& desc)
	: m_decl(decl), Tag(parent, name, desc)
{}

void UserTag::setParent(Tag* parent) {
	m_parent = parent;
}

Tag::Type UserTag::getType() {
	return getParent()->getType();
}

bool UserTag::isDefinedForDecl() {
	return getDeclaration() != nullptr;
}

void UserTag::setDeclaration(Function::FunctionDecl* decl) {
	m_decl = decl;
}

Function::FunctionDecl* UserTag::getDeclaration() {
	return m_decl;
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

Tag::Tag(Tag* parent, const std::string& name, const std::string& desc)
	: m_parent(parent), m_desc(name, desc)
{}

bool Tag::isUser() {
	return getParent() != nullptr;
}

Tag* Tag::getParent() {
	return m_parent;
}

Desc& Tag::getDesc() {
	return m_desc;
}
