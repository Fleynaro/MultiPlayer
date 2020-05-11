#include "FunctionTagCollection.h"

using namespace CE;
using namespace CE::Function::Tag;

TagCollection::TagCollection()
{}

TagCollection::TagCollection(TagCollection* collection)
{
	if (collection != nullptr) {
		add(*collection);
	}
}

void TagCollection::add(TagCollection& collection) {
	for (auto tag : collection.getTagList()) {
		add(tag);
	}
}

void TagCollection::add(Tag* tag) {
	getTagList().push_back(tag);
}

void TagCollection::remove(Tag* tag) {
	getTagList().remove(tag);
}

void TagCollection::clear() {
	getTagList().clear();
}

bool TagCollection::contains(Tag* tag) {
	for (auto tag_ : getTagList()) {
		if (tag == tag_)
			return true;
	}
	return false;
}

bool TagCollection::contains(TagCollection& collection) {
	for (auto tag : collection.getTagList()) {
		if (!contains(tag))
			return false;
	}
	return true;
}

bool TagCollection::empty() {
	return getTagList().empty();
}

std::list<Tag*>& TagCollection::getTagList() {
	return m_tagList;
}
