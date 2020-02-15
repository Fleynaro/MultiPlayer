#pragma once
#include "FunctionList.h"

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
					addFlags(ImGuiTreeNodeFlags_FramePadding);
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
			{}

			~TreeView() {
				if(m_eventUpdateCB != nullptr)
					delete m_eventUpdateCB;
			}

			//MY TODO*: unsetView
			void onSetView() override {
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
							tagChildNode->addFlags(ImGuiTreeNodeFlags_Leaf);
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
			virtual bool isFilterEnabled() {
				return /*m_cb_isFilterEnabled != nullptr && */m_cb_isFilterEnabled->isSelected();
			}

			FunctionTagList* m_funcTagList;
			Events::EventHandler* m_openFunctionTag;
			Events::EventHandler* m_eventUpdateCB = nullptr;
			Elements::Generic::Checkbox* m_cb_isFilterEnabled = nullptr;
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

			bool isFilterEnabled() override {
				return false;
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
		std::string getPlaceHolder() override {
			if (getSelectedFuncTagCount() == 0)
				return "No selected function tag(s)";

			std::string info = "";
			int max = 2;
			for (auto tag : getSelectedFunctionTags()) {
				info += tag->getName() + ",";
				if (--max == 0) break;
			}

			if (getSelectedFuncTagCount() > 2) {
				info += " ...";
			}
			else {
				info.pop_back();
			}

			return info.data();
		}

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


namespace GUI::Window
{
	class FunctionTagEditor
		: public IWindow
	{
	public:

		FunctionTagEditor(const std::string& name, CE::FunctionManager* funcManager, API::Function::Function* function)
			: IWindow(name), m_funcManager(funcManager)
		{
			setWidth(300);
			setHeight(300);
			setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar);

			getMainContainer()
				.text("Tag name")
				.addItem(m_nameInput = new Elements::Input::Text)

				.text("Select function parent tag")
				.addItem(m_funcTagInput = new Widget::FunctionTagInput(this, funcManager->getFunctionTagManager()))
				.newLine()

				.text("Select function")
				.addItem(m_funcInput = new Widget::FunctionInput(this, funcManager))
				.newLine()
				.newLine();

			if (function != nullptr) {
				m_funcInput->getSelectedFunctions().push_back(function);
			}
		}

	protected:
		CE::FunctionManager* m_funcManager;
		Elements::Input::Text* m_nameInput;
		Widget::FunctionInput* m_funcInput;
		Widget::FunctionTagInput* m_funcTagInput;

		bool checkData()
		{
			return m_funcInput->getSelectedFuncCount() > 0
				&& m_funcTagInput->getSelectedFuncTagCount() > 0
				&& !m_nameInput->getInputValue().empty();
		}
	};

	class FunctionTagCreator
		: public FunctionTagEditor
	{
	public:
		FunctionTagCreator(CE::FunctionManager* funcManager, API::Function::Function* function = nullptr)
			: FunctionTagEditor("Function tag creator", funcManager, function)
		{
			getMainContainer()
				.addItem(
					new Elements::Button::ButtonStd("Create", new Events::EventUI(
						EVENT_LAMBDA(info) {
							if(!checkData())
								return;

							auto tagManager = m_funcManager->getFunctionTagManager();
							auto func = *m_funcInput->getSelectedFunctions().begin();
							
							tagManager->createTag(
								func->getDeclaration(),
								*m_funcTagInput->getSelectedFunctionTags().begin(),
								m_nameInput->getInputValue()
							);
							hide();
						}
				)));
		}
	};

	class FunctionTagUpdater
		: public FunctionTagEditor
	{
	public:
		FunctionTagUpdater(CE::FunctionManager* funcManager, API::Function::Function* function, Function::Tag::Tag* tag)
			: FunctionTagEditor("Function tag editor", funcManager, function)
		{
			m_nameInput->setInputValue(tag->getName());
			m_funcTagInput->getSelectedFunctionTags().push_back(tag);

			getMainContainer()
				.addItem(
					new Elements::Button::ButtonStd("Change", new Events::EventUI(
						EVENT_LAMBDA(info) {
							if (!checkData())
								return;

							auto tagManager = m_funcManager->getFunctionTagManager();
							auto func = *m_funcInput->getSelectedFunctions().begin();

							auto tag = *m_funcTagInput->getSelectedFunctionTags().begin();
							if (tag->isUser()) {
								auto userTag = static_cast<Function::Tag::UserTag*>(tag);
								userTag->setDeclaration(func->getDeclaration());
								hide();
							}
					}
				)));
		}
	};
};


namespace GUI::Widget
{
	//MY TODO: в виде кнопок, при нажатии на которую вылетает алерт/меню с предложением изменить/удалить
	class FunctionTagShortCut
		: public Container
	{
	public:
		class TagBtn
			: public Elements::Button::ButtonTag
		{
		public:
			TagBtn(Function::Tag::Tag* tag, Events::EventHandler* eventHandler = nullptr)
				: m_tag(tag), Elements::Button::ButtonTag(tag->getName(), ColorRGBA(0x0000FFFF), eventHandler)
			{}

			std::string getHintText() override {
				return getTag()->getDesc();
			}

			Function::Tag::Tag* getTag() {
				return m_tag;
			}
		private:
			Function::Tag::Tag* m_tag;
		};

		FunctionTagShortCut(API::Function::Function* function, Window::IWindow* parentWindow = nullptr)
			: m_function(function), m_parentWindow(parentWindow)
		{
			if (m_parentWindow != nullptr) {
				m_clickOnTag = new Events::EventUI(
					EVENT_LAMBDA(info) {
						auto sender = static_cast<TagBtn*>(info->getSender());
						if (m_winEditor != nullptr)
							m_parentWindow->removeWindow(m_winEditor, true);
						m_parentWindow->addWindow(m_winEditor = new Window::FunctionTagUpdater(m_function->getFunctionManager(), m_function, sender->getTag()));
					}
				);

				m_clickOnCreateTag = new Events::EventUI(
					EVENT_LAMBDA(info) {
						if (m_winEditor != nullptr)
							m_parentWindow->removeWindow(m_winEditor, true);//MY TODO: break triggered error
						m_parentWindow->addWindow(m_winEditor = new Window::FunctionTagCreator(m_function->getFunctionManager()));
					}
				);
			}

			refresh();
		}

		~FunctionTagShortCut() {
			if (m_parentWindow != nullptr) {
				delete m_clickOnTag;
				delete m_clickOnCreateTag;
				if (m_winEditor != nullptr)
					m_parentWindow->removeWindow(m_winEditor, true);
			}
		}

		void refresh() {
			clear();
			auto collection = getTagCollection();
			for (auto tag : collection.getTagList()) {
				addItem(new TagBtn(tag, m_clickOnTag));
				sameLine();
			}
			if (collection.empty()) {
				text("Not tags. ");
				sameLine();
			}

			if(m_clickOnCreateTag != nullptr)
				addItem(new Elements::Button::ButtonTag("+", ColorRGBA(0x0000FFFF), m_clickOnCreateTag));
			
			newLine();
		}

		Function::Tag::TagCollection getTagCollection() {
			auto tagManager = m_function->getFunctionManager()->getFunctionTagManager();
			return tagManager->getTagCollection(m_function);
		}
	private:
		API::Function::Function* m_function;
		Events::EventHandler* m_clickOnTag = nullptr;
		Events::EventHandler* m_clickOnCreateTag = nullptr;
		Window::IWindow* m_parentWindow;
		Window::FunctionTagEditor* m_winEditor = nullptr;
	};

};