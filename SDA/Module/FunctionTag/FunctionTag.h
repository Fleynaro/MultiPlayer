#pragma once
#include <CallGraph/CallGraph.h>

namespace CE
{
	//MY TODO: ����������� ����
	namespace Function::Tag
	{
		class Tag : public Desc
		{
		public:
			enum Type
			{
				GET,
				SET
			};

			Tag(Tag* parent, int id, std::string name, std::string desc = "")
				: Desc(id, name, desc)
			{}

			virtual Type getType() = 0;

			bool isUser() {
				return getParent() != nullptr;
			}
			
			Tag* getParent() {
				return m_parent;
			}
		private:
			Tag* m_parent;
		};

		class GetTag : public Tag
		{
		public:
			GetTag()
				: Tag(nullptr, 1, "Get tag", "")
			{}

			Type getType() override {
				return GET;
			}
		};

		class SetTag : public Tag
		{
		public:
			SetTag()
				: Tag(nullptr, 2, "Set tag", "")
			{}

			Type getType() override {
				return SET;
			}
		};

		class UserTag : public Tag
		{
		public:
			UserTag(Tag* parent, int id, std::string name, std::string desc = "")
				: Tag(parent, id, name, desc)
			{}

			UserTag(API::Function::FunctionDecl* decl, Tag* parent, int id, std::string name, std::string desc = "")
				: m_decl(decl), Tag(parent, id, name, desc)
			{}

			Type getType() override {
				return getParent()->getType();
			}

			bool isDefinedForDecl() {
				return getDeclaration() != nullptr;
			}

			API::Function::FunctionDecl* getDeclaration() {
				return m_decl;
			}
		private:
			API::Function::FunctionDecl* m_decl = nullptr;
		};

		class TagCollection
		{
		public:
			TagCollection()
			{}

			void add(TagCollection& collection) {
				for (auto tag : collection.getTagList()) {
					add(tag);
				}
			}

			void add(Tag* tag) {
				getTagList().push_back(tag);
			}

			void remove(Tag* tag) {
				getTagList().remove(tag);
			}

			void clear() {
				getTagList().clear();
			}

			bool empty() {
				return getTagList().empty();
			}

			std::list<Tag*>& getTagList() {
				return m_tagList;
			}
		private:
			std::list<Tag*> m_tagList;
		};

		class Manager
		{
		public:
			using TagDict = std::map<int, Tag*>;
			using TagCollectionDict = std::map<int, TagCollection>;

			Manager(FunctionManager* funcManager)
				: m_funcManager(funcManager)
			{
				addTag(new GetTag);
				addTag(new SetTag);
			}

			void loadTags() {
				using namespace SQLite;

				SQLite::Database& db = getProgramModule()->getDB();
				SQLite::Statement query(db, "SELECT * FROM sda_func_tags ORDER BY parent_tag_id ASC");

				while (query.executeStep())
				{
					int tag_id = query.getColumn("tag_id");
					int parent_tag_id = query.getColumn("parent_tag_id");
					
					Tag* parentTag = getTagById(parent_tag_id);;
					if (parentTag == nullptr)
						continue;
					auto decl = m_funcManager->getFunctionDeclById(query.getColumn("decl_id"));

					addTag(new UserTag(decl, parentTag, tag_id, query.getColumn("name"), query.getColumn("desc")));
				}
			}

			void saveTag(UserTag& tag) {
				using namespace SQLite;

				SQLite::Database& db = getProgramModule()->getDB();
				{
					SQLite::Statement query(db, "REPLACE INTO sda_functions (tag_id, parent_tag_id, decl_id, name, desc) VALUES(?1, ?2, ?3, ?4, ?5)");
					query.bind(1, tag.getId());
					query.bind(2, tag.getParent()->getId());
					query.bind(3, tag.getDeclaration()->getFunctionDecl()->getId());
					query.bind(4, tag.getName());
					query.bind(5, tag.getDesc());
					query.exec();
				}
			}

			void addUserTags() {
				for (auto it : getTags()) {
					if (!it.second->isUser())
						continue;
					auto tag = static_cast<UserTag*>(it.second);
					TagCollection* collection = getGlobalTagCollectionByDecl(tag->getDeclaration(), true);
					collection->add(tag);
				}
			}

			void calculateAllTags() {
				m_tagCollections.clear();
				addUserTags();
				std::deque<std::pair<int, Tag*>> tags;
				
				using namespace CallGraph;
				CallGraphIterator iter(m_funcManager);
				iter.iterate([&](Unit::Node* node, CallStack& stack)
				{
					if(node->isFunctionBody())
					{
						while (!tags.empty()) {
							if (tags.front().first >= stack.size()) {
								tags.pop_front();
								continue;
							}
							break;
						}

						auto funcBody = static_cast<Unit::FunctionBody*>(node);
						TagCollection* gCollection = getGlobalTagCollectionByDecl(funcBody->getFunction()->getDeclaration());
						if (gCollection != nullptr) {
							for (auto tag : gCollection->getTagList()) {
								if (tag->getType() == Tag::GET) {
									tags.push_front(std::make_pair(stack.size(), tag));
								}
							}
						}

						if (!tags.empty()) {
							gCollection = getGlobalTagCollectionByDecl(funcBody->getFunction()->getDeclaration(), true);
							for (auto it : tags) {
								gCollection->add(it.second);
							}
						}
					}
					return true;
				});
			}

			TagDict& getTags() {
				return m_tags;
			}

			void addTag(Tag* tag) {
				m_tags.insert(std::make_pair(tag->getId(), tag));
			}

			inline Tag* getTagById(int id) {
				if (m_tags.find(id) == m_tags.end())
					return nullptr;
				return m_tags[id];
			}

			inline TagCollection* getGlobalTagCollectionByDecl(API::Function::FunctionDecl* decl, bool create = false) {
				auto decl_id = decl->getFunctionDecl()->getId();
				if (m_tagCollections.find(decl_id) == m_tagCollections.end()) {
					if (!create) {
						return nullptr;
					}
					m_tagCollections[decl_id] = TagCollection();
				}
				return &m_tagCollections[decl_id];
			}

			TagCollection getTagCollectionByDecl(API::Function::Function* function) {
				TagCollection collection;

				auto globalCollection = getGlobalTagCollectionByDecl(function->getDeclaration());
				if (globalCollection != nullptr) {
					collection.add(*globalCollection);
				}

				using namespace CallGraph;
				FunctionIterator pass(function->getBody());
				pass.iterateCallStack([&](Unit::Node* node, CallStack& stack)
				{
					auto funcNode = static_cast<Unit::FunctionNode*>(node);
					if (!funcNode->isNotCalculated()) {
						auto gCollection = getGlobalTagCollectionByDecl(funcNode->getFunction()->getDeclaration());
						if (gCollection != nullptr) {
							for (auto tag : gCollection->getTagList()) {
								if (tag->getType() == Tag::SET) {
									collection.add(tag);
								}
							}
						}
					}
					return true;
				}, FunctionIterator::Filter::FunctionNode);

				return collection;
			}

			ProgramModule* getProgramModule() {
				return m_funcManager->getProgramModule();
			}
		private:
			FunctionManager* m_funcManager;
			TagDict m_tags;
			TagCollectionDict m_tagCollections;
		};
	};
};

