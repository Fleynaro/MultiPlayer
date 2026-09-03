#pragma once
#include "FunctionTag.h"

namespace CE::Function::Tag
{
	class TagCollection
	{
	public:
		TagCollection();

		TagCollection(TagCollection* collection);

		void add(TagCollection& collection);

		void add(Tag* tag);

		void remove(Tag* tag);

		void clear();

		bool contains(Tag* tag);

		bool contains(TagCollection& collection);

		bool empty();

		std::list<Tag*>& getTags();
	private:
		std::list<Tag*> m_tagList;
	};
};