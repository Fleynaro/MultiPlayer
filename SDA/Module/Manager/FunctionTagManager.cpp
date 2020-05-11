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
			if (!userTag->isDefinedForDecl())
				continue;
			TagCollection* collection = getGlobalTagCollectionByDecl(userTag->getDeclaration(), true);
			collection->add(userTag);
		}
	}
}

void FunctionTagManager::calculateAllTags() {
	m_tagCollections.clear();
	calculateUserTags();
	std::deque<std::pair<int, Tag*>> tags;

	using namespace CodeGraph;
	CallGraphIterator iter(m_funcManager);
	iter.iterate([&](Node::Node* node, CallStack& stack)
		{
			if (auto funcBody = dynamic_cast<Node::FunctionBody*>(node))
			{
				while (!tags.empty()) {
					if (tags.front().first >= stack.size()) {
						tags.pop_front();
						continue;
					}
					break;
				}

				TagCollection tempCollection;
				for (auto it : tags) {
					tempCollection.add(it.second);
				}

				auto gCollection = getGlobalTagCollectionByDecl(funcBody->getFunction()->getDeclarationPtr());
				if (gCollection != nullptr) {
					for (auto tag : gCollection->getTagList()) {
						if (tag->getType() == Tag::GET) {
							tags.push_front(std::make_pair(stack.size(), tag));
						}
					}
				}

				if (!tempCollection.empty()) {
					gCollection = getGlobalTagCollectionByDecl(funcBody->getFunction()->getDeclarationPtr(), true);
					gCollection->add(tempCollection);
				}
			}
			return true;
		});
}

UserTag* FunctionTagManager::createUserTag(Function::FunctionDecl* decl, Tag* parent, std::string name, std::string desc) {
	UserTag* tag;
	if (decl != nullptr)
		tag = new UserTag(decl, parent, name, desc);
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

TagCollection* FunctionTagManager::getGlobalTagCollectionByDecl(Function::FunctionDecl* decl, bool create) {
	auto decl_id = decl->getId();
	if (m_tagCollections.find(decl_id) == m_tagCollections.end()) {
		if (!create) {
			return nullptr;
		}
		m_tagCollections[decl_id] = TagCollection();
	}
	return &m_tagCollections[decl_id];
}

TagCollection FunctionTagManager::getTagCollection(Function::Function* function) {
	TagCollection collection;

	auto globalCollection = getGlobalTagCollectionByDecl(function->getDeclarationPtr());
	if (globalCollection != nullptr) {
		collection.add(*globalCollection);
	}

	using namespace CodeGraph;
	FunctionBodyIterator it(function->getBody());
	it.iterateCallStack([&](Node::Node* node, CallStack& stack)
		{
			auto funcNode = static_cast<Node::FunctionNode*>(node);
			if (!funcNode->isNotCalculated()) {
				auto gCollection = getGlobalTagCollectionByDecl(funcNode->getFunction()->getDeclarationPtr());
				if (gCollection != nullptr) {
					for (auto tag : gCollection->getTagList()) {
						if (tag->getType() == Tag::SET && !collection.contains(tag)) {
							collection.add(tag);
						}
					}
				}
			}
			return true;
		}, FunctionBodyIterator::Filter::FunctionNode);

	return collection;
}
