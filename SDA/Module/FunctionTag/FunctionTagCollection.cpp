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
	for (auto tag : collection.getTags()) {
		add(tag);
	}
}

void TagCollection::add(Tag* tag) {
	getTags().push_back(tag);
}

void TagCollection::remove(Tag* tag) {
	getTags().remove(tag);
}

void TagCollection::clear() {
	getTags().clear();
}

bool TagCollection::contains(Tag* tag) {
	for (auto tag_ : getTags()) {
		if (tag == tag_)
			return true;
	}
	return false;
}

bool TagCollection::contains(TagCollection& collection) {
	for (auto tag : collection.getTags()) {
		if (!contains(tag))
			return false;
	}
	return true;
}

bool TagCollection::empty() {
	return getTags().empty();
}

std::list<Tag*>& TagCollection::getTags() {
	return m_tagList;
}
