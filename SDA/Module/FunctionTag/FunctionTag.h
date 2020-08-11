#pragma once
#include <Code/Function/FunctionDefinition.h>
#include <DB/DomainObject.h>
#include <Utils/Description.h>


//MY TODO: конфликтные теги, дефолтные теги set,get(реентерабельность),краш
namespace CE::Function::Tag
{
	class Tag : public DB::DomainObject, public Descrtiption
	{
	public:
		enum Type
		{
			GET,
			SET
		};

		Tag(Tag* parent, const std::string& name, const std::string& comment = "");

		virtual Type getType() = 0;

		bool isUser();

		Tag* getParent();
	protected:
		Tag* m_parent;
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
		UserTag(Tag* parent, const std::string& name, const std::string& comment = "");

		UserTag(Function* func, Tag* parent, const std::string& name, const std::string& comment = "");

		void setParent(Tag* parent);

		Type getType() override;

		bool isDefinedForFunc();

		void setFunction(Function* func);

		Function* getFunction();
	private:
		Function* m_function = nullptr;
	};
};