#pragma once
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include "GUI/Signature.h"
#include <Manager/FunctionManager.h>
#include <FunctionTag/FunctionTag.h>
#include "../ItemControlPanels/FunctionCP.h"
#include "../ProjectWindow.h"

using namespace CE;

namespace GUI::Widget
{
	class FunctionTagCreator
		: public Container
	{
	public:

		FunctionTagCreator()
		{}
	};

	class FunctionTagShortCut
		: public Container
	{
	public:

		FunctionTagShortCut()
		{}
	};

	class FunctionTagList : public Template::ItemList
	{
	public:
		class TreeView : public IView
		{
		public:
			class FunctionTag : public TreeNode
			{
			public:
				FunctionTag(Function::Tag::Tag* tag, Events::EventHandler* openFunctionTag)
					: m_tag(tag), m_openFunctionTag(openFunctionTag), TreeNode(tag->getName())
				{
					setLeftMouseClickEvent(openFunctionTag);
				}

				Function::Tag::Tag* getTag() {
					return m_tag;
				}
			private:
				Function::Tag::Tag* m_tag;
				Events::EventHandler* m_openFunctionTag;
			};
			
			TreeView(FunctionTagList* funcTagList, Events::EventHandler* openFunctionTag = nullptr)
				: m_funcTagList(funcTagList), m_openFunctionTag(openFunctionTag)
			{
				m_eventUpdateCB = new Events::EventUI(EVENT_LAMBDA(info) {
					m_funcTagList->update();
				});
				m_eventUpdateCB->setCanBeRemoved(false);

				(*m_funcTagList->m_underFilterCP)
					.beginReverseInserting()
						.beginContainer()
							.newLine()
							.separator()
							.addItem(m_cb_isFilterEnabled = new Elements::Generic::Checkbox("Use filters and search", false, m_eventUpdateCB))
						.end()
					.endReverseInserting();
			}

			~TreeView() {
				delete m_eventUpdateCB;
			}

			void load(FunctionTag* tagNode, bool& remove, const std::string& funcName) {
				remove = true;
				
				for (auto tag : m_funcTagList->m_funcTagManager->getTags()) {
					if (!tag.second->isUser())
						continue;
					if (tag.second->getParent()->getId() == tagNode->getTag()->getId()) {
						FunctionTag* tagChildNode;
						bool isRemove;
						load(tagChildNode = new FunctionTag(tag.second, m_openFunctionTag), isRemove, funcName);
						
						if (isFilterEnabled()) {
							if (tagChildNode->empty()) {
								if (m_funcTagList->checkOnInputValue(tagChildNode->getTag(), funcName)
									&& m_funcTagList->checkAllFilters(tagChildNode->getTag())) {
									remove = false;
									isRemove = false;
								}
							}

							if (isRemove) {
								delete tagChildNode;
							}
							else {
								tagNode->addItem(tagChildNode);
							}
						}
					}
				}
			}

			void onSearch(const std::string& tagName) override
			{
				m_funcTagList->getItemsContainer().clear();
				
				for(auto tag : m_funcTagList->m_funcTagManager->m_basicTags)
				{
					FunctionTag* tagNode;
					m_funcTagList->getItemsContainer().addItem(tagNode = new FunctionTag(tag, m_openFunctionTag));
					bool isRemove;
					load(tagNode, isRemove, tagName);
				}
			}
		private:
			bool isFilterEnabled() {
				return m_cb_isFilterEnabled->isSelected();
			}
		private:
			FunctionTagList* m_funcTagList;
			Events::EventHandler* m_openFunctionTag;
			Events::EventHandler* m_eventUpdateCB;
			Elements::Generic::Checkbox* m_cb_isFilterEnabled;
		};
		friend class TreeView;

		class FunctionTagFilter : public FilterManager::Filter
		{
		public:
			FunctionTagFilter(const std::string& name, FunctionTagList* functionTagList)
				: Filter(functionTagList->getFilterManager(), name), m_functionTagList(functionTagList)
			{}

			virtual bool checkFilter(Function::Tag::Tag* tag) = 0;

		protected:
			FunctionTagList* m_functionTagList;
		};

		class FunctionTagFilterCreator : public FilterManager::FilterCreator
		{
		public:
			FunctionTagFilterCreator(FunctionTagList* functionTagList)
				: m_functionTagList(functionTagList), FilterCreator(functionTagList->getFilterManager())
			{
				//addItem("Category filter");
			}

			FilterManager::Filter* createFilter(int idx) override
			{
				switch (idx)
				{
				//case 0: return new CategoryFilter(m_funcList);
				}
				return nullptr;
			}

		private:
			FunctionTagList* m_functionTagList;
		};

		FunctionTagList(Function::Tag::Manager* funcTagManager)
			: ItemList(new FunctionTagFilterCreator(this)), m_funcTagManager(funcTagManager)
		{
			//getFilterManager()->addFilter(new CategoryFilter(this));
		}

		bool checkOnInputValue(Function::Tag::Tag* tag, const std::string& value) {
			return Generic::String::ToLower(tag->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(Function::Tag::Tag* tag) {
			return getFilterManager()->check([&tag](FilterManager::Filter* filter) {
				return static_cast<FunctionTagFilter*>(filter)->checkFilter(tag);
			});
		}
	private:
		Function::Tag::Manager* m_funcTagManager;
	};
};

namespace GUI::Window
{
	class FunctionTagList : public IWindow
	{
	public:
		FunctionTagList(Function::Tag::Manager* funcTagManager, Events::EventHandler* openFunctionTag)
			: IWindow("Function tag list")
		{
			Widget::FunctionTagList* funcTagList;
			setMainContainer(funcTagList = new Widget::FunctionTagList(funcTagManager));
			funcTagList->setView(new Widget::FunctionTagList::TreeView(funcTagList, openFunctionTag));
		}

		Widget::FunctionTagList* getList() {
			return static_cast<Widget::FunctionTagList*>(getMainContainerPtr());
		}
	};
};