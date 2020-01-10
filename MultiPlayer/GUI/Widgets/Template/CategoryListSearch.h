#pragma once

#include "../../Items/IWidget.h"

namespace GUI::Widget::Template
{
	class CategoryListSearch : public IWidget
	{
	public:
		class Category;

		GUI::Elements::Button::ButtonStd* m_retBackBtn = nullptr;
		CategoryListSearch()
			: IWidget("Category list search")
		{
			getMainContainer()
				.addItem(
					new GUI::Elements::Input::Text(
						"", 40, new Events::EventUI(EVENT_METHOD_PASS(search))
					)
				)
				.sameLine().addItem(
					new GUI::Elements::Button::ButtonStd(
						"Return back",
						new Events::EventUI(
							EVENT_LAMBDA(info) {
								update();
								m_retBackBtn->setDisplay(false);
							}
						)
					),
					(GUI::Item**)&m_retBackBtn
				)
				.newLine();

			m_retBackBtn->setDisplay(false);
		}
		
		std::string lastInputValue;
		EVENT_METHOD(search, info)
		{
			auto sender = (GUI::Elements::Input::Text*)info->getSender();

			std::string inputValue = String::ToLower(sender->getInputValue().c_str());
			updateOnInputValue(inputValue);
			lastInputValue = inputValue;
		}

		virtual void updateOnInputValue(std::string inputValue)
		{
			auto inputWords = String::Split(inputValue, "[ ,|]");

			for (auto category : getCatList()) {
				int relItemCount = 0;

				auto items = category->getItems();
				for (auto it : items)
				{
					if (inputValue.empty() || it->isRelevant(inputWords))
					{
						it->getContainer()->setDisplay(true);
						relItemCount++;
					}
					else {
						it->getContainer()->setDisplay(false);
					}
				}
				
				category->m_relItemCount = relItemCount;
			}
		}

		void showAll() {
			lastInputValue = "";
			update();
		}

		void update() {
			updateOnInputValue(lastInputValue);
		}

		void hideAllCategories() {
			for (auto category : getCatList()) {
				if (category->m_relItemCount > 0) {
					category->m_relItemCount *= -1;
				}
			}
		}

		void showCategory(Category* category) {
			if (!category->isHide())
				return;
			category->m_relItemCount *= -1;
		}

		void hideCategory(Category* category) {
			if (category->isHide())
				return;
			category->m_relItemCount *= -1;
		}

		bool m_showItemCount = true;

		class Item
		{
		public:
			Item(Container* container = new Container)
				: m_container(container)
			{}

			Item* setKeywordList(const std::list<std::string>& keywords) {
				m_keywords.insert(m_keywords.begin(), keywords.begin(), keywords.end());
				return this;
			}

			std::list<std::string>& getKeywords() {
				return m_keywords;
			}

			bool isRelevant(const std::vector<std::string>& inputWords) {
				for (auto word : inputWords) {
					bool isFound = false;
					for (auto keyword : m_keywords) {
						if (keyword.find(word) != std::string::npos) {
							isFound = true;
							break;
						}
					}
					if (!isFound) {
						return false;
					}
				}
				return true;
			}
			
			Category* getParent() {
				return (Category*)getContainer()->getParent();
			}

			template<typename T = Container>
			T* getContainer() {
				return (T*)m_container;
			}
		private:
			std::list<std::string> m_keywords;
			Container* m_container;
		};

		class Category : public TreeNode
		{
			friend class CategoryListSearch;
		public:
			Category(std::string name, CategoryListSearch* parent)
				: TreeNode(name, false), m_parent(parent)
			{}
			~Category() {
				for (auto it : m_items)
					delete it;
			}

			void render() override {
				if (!isHide()) {
					TreeNode::render();
				}
			}

			std::string getName() override {
				if (m_parent->m_showItemCount)
					return TreeNode::getName() + " (" + std::to_string(m_relItemCount) + " items)";
				else return TreeNode::getName();
			}
			
			Category& addItem(CategoryListSearch::Item* item) {
				TreeNode::addItem(item->getContainer());
				m_items.push_back(item);
				return *this;
			}

			Category& addItem(std::string name, const std::list<std::string>& keywords) {
				return addItem(
					(new CategoryListSearch::Item(new TreeNode(name, false)))
					->setKeywordList(keywords)
				);
			}

			std::list<CategoryListSearch::Item*>& getItems() {
				return m_items;
			}

			CategoryListSearch& endCategory() {
				return *m_parent;
			}

			bool isHide() {
				return m_relItemCount <= 0;
			}

			void* m_externalPtr = nullptr;
			int m_relItemCount = 0;
		private:
			CategoryListSearch* m_parent = nullptr;
			std::list<CategoryListSearch::Item*> m_items;
		};

		Category& beginCategory(std::string name) {
			auto newCat = newCategory(name);
			getMainContainer().addItem(newCat);
			return *newCat;
		}

		Category* newCategory(std::string name) {
			auto newCat = new Category(name, this);
			m_catList.push_back(newCat);
			return newCat;
		}

		Category* getCategoryByExPtr(void* ptr) {
			for (auto it : getCatList()) {
				if (it->m_externalPtr == ptr) {
					return it;
				}
			}
			return nullptr;
		}

		void clearCats()
		{
			m_catList.clear();
		}

		std::list<Category*>& getCatList() {
			return m_catList;
		}
	private:
		std::list<Category*> m_catList;
	};
};