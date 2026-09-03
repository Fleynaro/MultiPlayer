#pragma once
#include "AbstractManager.h"
#include <FunctionTag/FunctionTagCollection.h>
#include <Code/Function/Function.h>

namespace DB {
	class FunctionUserTagMapper;
};

namespace CE
{
	using namespace Function::Tag;

	class FunctionTagManager : public AbstractItemManager
	{
		using TagCollectionMapType = std::map<DB::Id, TagCollection>;
	public:
		using Iterator = AbstractIterator<Tag>;

		GetTag* m_getTag = new GetTag;
		SetTag* m_setTag = new SetTag;
		std::list<Tag*> m_basicTags;

		FunctionTagManager(ProgramModule* module, FunctionManager* funcManager);

		~FunctionTagManager();

		void loadUserTags();

		void calculateAllTags();

		UserTag* createUserTag(Function::Function* func, Tag* parent, std::string name, std::string desc = "");

		UserTag* createUserTag(Tag* parent, std::string name, std::string desc = "");

		Tag* getTagById(int id);

		TagCollection* getGlobalTagCollectionByFunc(Function::Function* func, bool create = false);

		TagCollection getTagCollection(Function::Function* function);
	private:
		FunctionManager* m_funcManager;
		TagCollectionMapType m_tagCollections;
		DB::FunctionUserTagMapper* m_userTagMapper;

		void calculateUserTags();
	};
};