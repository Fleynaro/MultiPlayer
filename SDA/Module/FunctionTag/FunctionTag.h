#pragma once
#include <Code/Function/FunctionDeclaration.h>
#include <DB/DomainObject.h>
#include "../Code/Shared.h"


//MY TODO: конфликтные теги, дефолтные теги set,get(реентерабельность),краш
namespace CE::Function::Tag
{
	class Tag : public DB::DomainObject
	{
	public:
		enum Type
		{
			GET,
			SET
		};

		Tag(Tag* parent, const std::string& name, const std::string& desc = "");

		virtual Type getType() = 0;

		bool isUser();

		Tag* getParent();

		Desc& getDesc();
	protected:
		Tag* m_parent;

	private:
		Desc m_desc;
	};

	class GetTag : public Tag
	{
	public:
		GetTag();

		Type getType() override;
	};

	class SetTag : public Tag
	{
	public:
		SetTag();

		Type getType() override;
	};

	class UserTag : public Tag
	{
	public:
		UserTag(Tag* parent, const std::string& name, const std::string& desc = "");

		UserTag(FunctionDecl* decl, Tag* parent, const std::string& name, const std::string& desc = "");

		void setParent(Tag* parent);

		Type getType() override;

		bool isDefinedForDecl();

		void setDeclaration(FunctionDecl* decl);

		FunctionDecl* getDeclaration();
	private:
		FunctionDecl* m_decl = nullptr;
	};
};