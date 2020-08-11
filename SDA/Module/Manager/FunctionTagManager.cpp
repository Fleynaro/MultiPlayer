#include "FunctionTagManager.h"
#include <DB/Mappers/FunctionTagMapper.h>

using namespace CE;

FunctionTagManager::FunctionTagManager(ProgramModule* module, FunctionManager* funcManager)
	: AbstractItemManager(module), m_funcManager(funcManager)
{
	m_userTagMapper = new DB::FunctionUserTagMapper(this);
	m_items.insert({
		std::make_pair(m_getTag->getId(), m_getTag),
		std::make_pair(m_setTag->getId(), m_setTag)
		});
	m_basicTags = { m_getTag, m_setTag };
}

FunctionTagManager::~FunctionTagManager() {
	delete m_getTag;
	delete m_setTag;
}

void FunctionTagManager::loadUserTags() {
	m_userTagMapper->loadAll();
}

void FunctionTagManager::calculateUserTags() {
	Iterator it(this);
	while (it.hasNext()) {
		auto tag = it.next();
		if (auto userTag = dynamic_cast<UserTag*>(tag)) {
			if (!userTag->isDefinedForFunc())
				continue;
			TagCollection* collection = getGlobalTagCollectionByFunc(userTag->getFunction(), true);
			collection->add(userTag);
		}
	}
}

void FunctionTagManager::calculateAllTags() {
	m_tagCollections.clear();
	calculateUserTags();
	std::deque<std::pair<int, Tag*>> tags;

	using namespace CodeGraph;
	//removed code...
}

UserTag* FunctionTagManager::createUserTag(Function::Function* func, Tag* parent, std::string name, std::string desc) {
	UserTag* tag;
	if (func != nullptr)
		tag = new UserTag(func, parent, name, desc);
	else tag = new UserTag(parent, name, desc);

	tag->setMapper(m_userTagMapper);
	tag->setId(m_userTagMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(tag);
	return tag;
}

UserTag* FunctionTagManager::createUserTag(Tag* parent, std::string name, std::string desc) {
	return createUserTag(nullptr, parent, name, desc);
}

Tag* FunctionTagManager::getTagById(int id) {
	return static_cast<Tag*>(find(id));
}

TagCollection* FunctionTagManager::getGlobalTagCollectionByFunc(Function::Function* func, bool create) {
	auto func_id = func->getId();
	if (m_tagCollections.find(func_id) == m_tagCollections.end()) {
		if (!create) {
			return nullptr;
		}
		m_tagCollections[func_id] = TagCollection();
	}
	return &m_tagCollections[func_id];
}

TagCollection FunctionTagManager::getTagCollection(Function::Function* function) {
	TagCollection collection;

	auto globalCollection = getGlobalTagCollectionByFunc(function);
	if (globalCollection != nullptr) {
		collection.add(*globalCollection);
	}

	using namespace CodeGraph;
	//removed code...

	return collection;
}
