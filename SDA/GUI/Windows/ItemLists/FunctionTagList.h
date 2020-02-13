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
					: m_tag(tag)
				{
					setLeftMouseClickEvent(openFunctionTag);
					
					m_header = new Container;
					(*m_header)
						.text(tag->getName());
				}

				~FunctionTag() {
					delete m_header;
				}

				void renderHeader() override {
					m_header->show();
				}

				Function::Tag::Tag* getTag() {
					return m_tag;
				}
			private:
				Function::Tag::Tag* m_tag;
			protected:
				Container* m_header;
			};

			class UserFunctionTag : public FunctionTag
			{
			public:
				UserFunctionTag(Function::Tag::UserTag* tag, Events::EventHandler* openFunctionTag)
					: FunctionTag(tag, openFunctionTag)
				{
					if (getTag()->isDefinedForDecl()) {
						if (m_signature == nullptr) {
							m_signature = new Units::DeclSignature(getTag()->getDeclaration());
						}
						(*m_header)
							.sameText(": ")
							.sameLine()
							.addItem(m_signature);
					}
				}

				~UserFunctionTag() {
					if (m_signature != nullptr) {
						delete m_signature;
					}
				}

				Function::Tag::UserTag* getTag() {
					return static_cast<Function::Tag::UserTag*>(FunctionTag::getTag());
				}
			private:
				Units::DeclSignature* m_signature = nullptr;
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
				tagNode->setAlwaysOpened(true);
				remove = true;
				
				for (auto tag : m_funcTagList->m_funcTagManager->getTags()) {
					if (!tag.second->isUser())
						continue;
					if (tag.second->getParent()->getId() == tagNode->getTag()->getId()) {
						FunctionTag* tagChildNode;
						bool isRemove;
						load(tagChildNode = createUserFunctionTag(static_cast<Function::Tag::UserTag*>(tag.second)), isRemove, funcName);
						tagNode->addItem(tagChildNode);
						if (tagChildNode->empty()) {
							tagChildNode->setNotTreeNode(true);
						}

						if (isFilterEnabled()) {
							if (tagChildNode->empty()) {
								if (m_funcTagList->checkOnInputValue(tagChildNode->getTag(), funcName)
									&& m_funcTagList->checkAllFilters(tagChildNode->getTag())) {
									remove = false;
									isRemove = false;
								}
							}

							if (isRemove) {
								tagNode->removeLastItem();
							}
						}
					}
				}
			}

			virtual FunctionTag* createUserFunctionTag(Function::Tag::UserTag* tag) {
				return new UserFunctionTag(tag, m_openFunctionTag);
			}

			void onSearch(const std::string& tagName) override
			{
				getOutContainer()->clear();
				
				for(auto tag : m_funcTagList->m_funcTagManager->m_basicTags)
				{
					FunctionTag* tagNode;
					getOutContainer()->addItem(tagNode = new FunctionTag(tag, m_openFunctionTag));
					bool isRemove;
					load(tagNode, isRemove, tagName);
				}
			}
		protected:
			bool isFilterEnabled() {
				return m_cb_isFilterEnabled->isSelected();
			}

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


	class FuncTagSelectList : public FunctionTagList
	{
	public:
		class SelectedFilter : public FunctionTagFilter
		{
		public:
			SelectedFilter(FuncTagSelectList* functionTagList)
				: FunctionTagFilter("Selected function tag filter", functionTagList)
			{
				buildHeader("Filter function tag by selected.", true);
				beginBody()
					.addItem(
						m_cb = new Elements::Generic::Checkbox("show selected only", false,
							new Events::EventUI(EVENT_LAMBDA(info) {
								onChanged();
							})
						)
					);
			}

			bool checkFilter(Function::Tag::Tag* tag) override {
				return static_cast<FuncTagSelectList*>(m_functionTagList)->isFunctionTagSelected(tag);
			}

			bool isDefined() override {
				return m_cb->isSelected();
			}
		private:
			Elements::Generic::Checkbox* m_cb;
		};

		class TreeView
			: public FunctionTagList::TreeView
		{
		public:
			class UserFunctionTagWithCheckBox : public UserFunctionTag
			{
			public:
				UserFunctionTagWithCheckBox(Function::Tag::UserTag* tag, Events::EventHandler* openFunctionTag, bool selected, Events::Event* eventSelectFunction)
					: UserFunctionTag(tag, openFunctionTag)
				{
					(*m_header)
						.beginReverseInserting()
							.sameLine()
							.addItem(new Elements::Generic::Checkbox("", selected, eventSelectFunction))
						.endReverseInserting();
				}
			};

			TreeView(FunctionTagList* funcTagList, Events::EventHandler* openFunctionTag = nullptr)
				: FunctionTagList::TreeView(funcTagList, openFunctionTag)
			{}

			FunctionTag* createUserFunctionTag(Function::Tag::UserTag* tag) override {
				return new UserFunctionTagWithCheckBox(tag, m_openFunctionTag, getFuncTagSelList()->isFunctionTagSelected(tag),
					new Events::EventHook(getFuncTagSelList()->m_eventSelectFunctionTag, tag));
			}
		protected:
			FuncTagSelectList* getFuncTagSelList() {
				return static_cast<FuncTagSelectList*>(m_funcTagList);
			}
		};


		FuncTagSelectList(Function::Tag::Manager* funcTagManager, Events::Event* eventSelectFunctionTags)
			: FunctionTagList(funcTagManager)
		{
			getFilterManager()->addFilter(new SelectedFilter(this));

			m_eventSelectFunctionTag = new Events::EventUI(EVENT_LAMBDA(info) {
				auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
				auto chekbox = static_cast<Elements::Generic::Checkbox*>(message->getRealSender());
				auto tag = (Function::Tag::Tag *)message->getUserDataPtr();
				if (chekbox->isSelected()) {
					getSelectedFunctionTags().push_back(tag);
				}
				else {
					getSelectedFunctionTags().remove(tag);
				}
			});

			class UpdSelectInfo : public Container
			{
			public:
				UpdSelectInfo(FuncTagSelectList* funcTagSelList, Events::Event* event)
					: m_funcTagSelList(funcTagSelList)
				{
					newLine();
					newLine();
					separator();
					addItem(m_button = new Elements::Button::ButtonStd("Select", event));
				}

				void render() override {
					Container::render();
					m_button->setName("Select " + std::to_string(m_funcTagSelList->getSelectedFuncTagCount()) + " function tags");
				}

				bool isShown() override {
					return m_funcTagSelList->getSelectedFuncTagCount() > 0;
				}
			private:
				FuncTagSelectList* m_funcTagSelList;
				Elements::Button::ButtonStd* m_button;
			};

			if (eventSelectFunctionTags != nullptr) {
				(*m_underFilterCP)
					.addItem(new UpdSelectInfo(this, eventSelectFunctionTags));
			}
		}

		bool isFunctionTagSelected(Function::Tag::Tag* tag) {
			for (auto tag_ : getSelectedFunctionTags()) {
				if (tag_ == tag)
					return true;
			}
			return false;
		}

		int getSelectedFuncTagCount() {
			return getSelectedFunctionTags().size();
		}

		std::list<Function::Tag::Tag*>& getSelectedFunctionTags() {
			return m_selectedFunctionTags;
		}
	private:
		std::list<Function::Tag::Tag*> m_selectedFunctionTags;
		Events::Event* m_eventSelectFunctionTag;
	};
};

namespace GUI::Window
{
	class FunctionTagList : public IWindow
	{
	public:
		FunctionTagList(Widget::FunctionTagList* funcTagList, const std::string& name = "Function tag list")
			: IWindow(name)
		{
			setMainContainer(funcTagList);
		}

		Widget::FunctionTagList* getList() {
			return static_cast<Widget::FunctionTagList*>(getMainContainerPtr());
		}
	};
};

namespace GUI::Widget
{
	class FunctionTagInput : public Template::ItemInput
	{
	public:
		FunctionTagInput(Window::IWindow* parentWindow, Function::Tag::Manager* funcTagManager)
			: m_parentWindow(parentWindow)
		{
			m_funcTagList = new FuncTagSelectList(funcTagManager, nullptr);
			m_funcTagList->setView(
				m_funcTagListView = new FuncTagSelectList::TreeView(m_funcTagList));
			m_funcTagList->setCanBeRemoved(false);

			m_funcTagListShortView = new FuncTagSelectList::TreeView(m_funcTagList);
			m_funcTagListShortView->setOutputContainer(m_funcTagShortList = new Container);
		}

		~FunctionTagInput() {
			if (m_window != nullptr) {
				m_parentWindow->removeWindow(m_window);
			}
			delete m_funcTagList;
			delete m_funcTagListView;
			delete m_funcTagListShortView;
			delete m_funcTagShortList;
		}

		int getSelectedFuncTagCount() {
			return getSelectedFunctionTags().size();
		}

		std::list<Function::Tag::Tag*>& getSelectedFunctionTags() {
			return m_funcTagList->getSelectedFunctionTags();
		}
	protected:
		std::string toolTip() override {
			if (getSelectedFuncTagCount() == 0)
				return "please, select one or more function tags";
			return "selected " + std::to_string(getSelectedFuncTagCount()) + " function tags";
		}

		void onSearch(const std::string& text) {
			m_funcTagListShortView->onSearch(text);
		}

		void renderShortView() override {
			m_funcTagShortList->show();
		}

		void renderSelectable(bool& open) override {
			if (getSelectedFuncTagCount() > 0) {
				std::string info = "Clear (" + toolTip() + ")";
				if (ImGui::Selectable(info.c_str())) {
					getSelectedFunctionTags().clear();
					m_funcTagShortList->clear();
					refresh();
				}
			}

			if (ImGui::Selectable("More...")) {
				if (m_window == nullptr) {
					m_parentWindow->addWindow(
						m_window = new Window::FunctionTagList(m_funcTagList, "Select function tags")
					);
					m_window->setCloseEvent(
						new Events::EventUI(
							EVENT_LAMBDA(info) {
								m_parentWindow->removeWindow(m_window);
								delete m_window;
								m_window = nullptr;
							}
						)
					);
					open = false;
				}
			}
		}

	private:
		Window::IWindow* m_parentWindow;
		Window::IWindow* m_window = nullptr;
		FuncTagSelectList* m_funcTagList;
		FuncTagSelectList::TreeView* m_funcTagListView;
		FuncTagSelectList::TreeView* m_funcTagListShortView;
		Container* m_funcTagShortList;
	};
};


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

};