#pragma once
#include "FunctionList.h"

using namespace CE;

namespace GUI::Widget
{
	using FuncTagEventType = Events::Event<Events::ISender*, Function::Tag::Tag*>;

	class IFunctionTagList
	{
	public:
		virtual Function::Tag::Manager* getManager() = 0;
		virtual Template::ItemList* getItemList() = 0;
		virtual bool checkOnInputValue(Function::Tag::Tag* tag, const std::string& value) = 0;
		virtual bool checkAllFilters(Function::Tag::Tag* tag) = 0;
	};

	//MY TODO: исчезают некоторые теги в tree view, не добавл€ютс€ новые, по дефу устанавливать в окне создани€ тега функцию
	class FunctionTagList
		: public Template::ItemList,
		public IFunctionTagList
	{
	public:
		class TreeView : public IView
		{
		public:
			class FunctionTag
				: public Item
			{
			public:
				FunctionTag(Function::Tag::Tag* tag, FuncTagEventType::EventHandlerType* openFunctionTag)
					: m_tag(tag), m_openFunctionTag(openFunctionTag)
				{
					addFlags(ImGuiTreeNodeFlags_FramePadding);
					getLeftMouseClickEvent() += [=](Events::ISender* sender) {
						if(openFunctionTag != nullptr)
							openFunctionTag->invoke(this, tag);
					};

					beginHeader()
						.text(tag->getName());
				}

				void renderHeader() override {
					m_header->show();
				}

				Function::Tag::Tag* getTag() {
					return m_tag;
				}
			private:
				Function::Tag::Tag* m_tag;
				FuncTagEventType::EventHandlerType* m_openFunctionTag;
			};

			class UserFunctionTag : public FunctionTag
			{
			public:
				UserFunctionTag(Function::Tag::UserTag* tag, FuncTagEventType::EventHandlerType* openFunctionTag)
					: FunctionTag(tag, openFunctionTag)
				{
					if (getTag()->isDefinedForDecl()) {
						(*m_header)
							.sameText(": ")
							.sameLine()
							.addItem(new Units::DeclSignature(getTag()->getDeclaration()));
					}
				}

				Function::Tag::UserTag* getTag() {
					return static_cast<Function::Tag::UserTag*>(FunctionTag::getTag());
				}
			};

			TreeView(IFunctionTagList* funcTagList, FuncTagEventType::EventHandlerType* openFunctionTag = nullptr)
				: m_funcTagList(funcTagList), m_openFunctionTag(openFunctionTag)
			{}

			~TreeView() {
				if (m_eventUpdateCB != nullptr)
					delete m_eventUpdateCB;
			}

			//MY TODO*: unsetView
			void onSetView() override {
				m_eventUpdateCB = Events::Listener(
					std::function([&](Events::ISender* sender) {
						m_funcTagList->getItemList()->update();
						})
				);
				m_eventUpdateCB->setCanBeRemoved(false);

				(*m_funcTagList->getItemList()->m_underFilterCP)
					.beginReverseInserting()
					.beginContainer()
					.newLine()
					.separator()
					.addItem(m_cb_isFilterEnabled = new Elements::Generic::Checkbox("Use filters", false, m_eventUpdateCB))
					.end()
					.endReverseInserting();
			}

			void load(FunctionTag* tagNode, bool& remove, const std::string& funcName) {
				tagNode->setAlwaysOpened(true);
				remove = true;

				for (auto tag : m_funcTagList->getManager()->getTags()) {
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
									&& (isSearchOnlyEnabled() || m_funcTagList->checkAllFilters(tagChildNode->getTag()))) {
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

			virtual UserFunctionTag* createUserFunctionTag(Function::Tag::UserTag* tag) {
				return new UserFunctionTag(tag, m_openFunctionTag);
			}

			void onSearch(const std::string& tagName) override
			{
				getOutContainer()->clear();

				for (auto tag : m_funcTagList->getManager()->m_basicTags)
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

			virtual bool isSearchOnlyEnabled() {
				return false;
			}

			IFunctionTagList* m_funcTagList;
			FuncTagEventType::EventHandlerType* m_openFunctionTag;
			Events::SpecialEventType::EventHandlerType* m_eventUpdateCB = nullptr;
			Elements::Generic::Checkbox* m_cb_isFilterEnabled = nullptr;
		};
		friend class TreeView;

		class FunctionTagFilter : public Template::FilterManager::Filter
		{
		public:
			FunctionTagFilter(const std::string& name, FunctionTagList* functionTagList)
				: Filter(functionTagList->getFilterManager(), name), m_functionTagList(functionTagList)
			{}

			virtual bool checkFilter(Function::Tag::Tag* tag) = 0;

		protected:
			FunctionTagList* m_functionTagList;
		};

		class FunctionTagFilterCreator : public Template::FilterManager::FilterCreator
		{
		public:
			FunctionTagFilterCreator(FunctionTagList* functionTagList)
				: m_functionTagList(functionTagList), FilterCreator(functionTagList->getFilterManager())
			{
				//addItem("Category filter");
			}

			Template::FilterManager::Filter* createFilter(int idx) override
			{
				/*switch (idx)
				{
					case 0: return new CategoryFilter(m_funcList);
				}*/
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

		bool checkOnInputValue(Function::Tag::Tag* tag, const std::string& value) override {
			return Generic::String::ToLower(tag->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(Function::Tag::Tag* tag) override {
			return getFilterManager()->check([&tag](Template::FilterManager::Filter* filter) {
				return static_cast<FunctionTagFilter*>(filter)->checkFilter(tag);
				});
		}

		Template::ItemList* getItemList() override {
			return this;
		}

		Function::Tag::Manager* getManager() override {
			return m_funcTagManager;
		}
	private:
		Function::Tag::Manager* m_funcTagManager;
	};


	class FuncTagSelectList
		: public Template::SelectableItemList<Function::Tag::Tag>,
		public IFunctionTagList
	{
	public:
		class TreeView
			: public FunctionTagList::TreeView
		{
		public:
			TreeView(FuncTagSelectList* funcTagSelectList, FuncTagEventType::EventHandlerType* openFunctionTag = nullptr)
				: m_funcTagSelectList(funcTagSelectList), FunctionTagList::TreeView(funcTagSelectList, openFunctionTag)
			{}

			UserFunctionTag* createUserFunctionTag(Function::Tag::UserTag* tag) override {
				auto funcTagItem = FunctionTagList::TreeView::createUserFunctionTag(tag);
				makeSelectable(
					funcTagItem,
					tag,
					m_funcTagSelectList->isItemSelected(tag),
					m_funcTagSelectList->m_eventSelectItem
				);
				return funcTagItem;
			}
		protected:
			FuncTagSelectList* m_funcTagSelectList;

			bool isFilterEnabled() override {
				return true;
			}

			bool isSearchOnlyEnabled() override {
				return true;
			}
		};

		FuncTagSelectList(FunctionTagList* functionTagList, Events::SpecialEventType::EventHandlerType* eventSelectFunctionTagsBtn)
			: Template::SelectableItemList<Function::Tag::Tag>(functionTagList, eventSelectFunctionTagsBtn)
		{}

		FunctionTagList* getFuncTagList() {
			return static_cast<FunctionTagList*>(m_itemList);
		}

		bool checkOnInputValue(Function::Tag::Tag* tag, const std::string& value) override {
			return getFuncTagList()->checkOnInputValue(tag, value);
		}

		bool checkAllFilters(Function::Tag::Tag* tag) override {
			return getFilterManager()->check([&](Template::FilterManager::Filter* filter) {
				return filter == m_selectedFilter
					? static_cast<SelectedFilter*>(filter)->checkFilter(tag)
					: static_cast<FunctionTagList::FunctionTagFilter*>(filter)->checkFilter(tag);
				});
		}

		Template::ItemList* getItemList() override {
			return this;
		}

		Function::Tag::Manager* getManager() override {
			return getFuncTagList()->getManager();
		}
	};
};

namespace GUI::Window
{
	class FunctionTagList : public IWindow
	{
	public:
		FunctionTagList(Widget::IFunctionTagList* funcTagList, const std::string& name = "Function tag list")
			: m_funcTagList(funcTagList), IWindow(name)
		{
			setMainContainer(m_funcTagList->getItemList());
		}

		Widget::IFunctionTagList* getList() {
			return m_funcTagList;
		}
	private:
		Widget::IFunctionTagList* m_funcTagList;
	};
};

namespace GUI::Widget
{
	class FunctionTagInput : public Template::ItemInput
	{
	public:
		FunctionTagInput(Function::Tag::Manager* funcTagManager)
		{
			m_funcTagList = new FuncTagSelectList(new FunctionTagList(funcTagManager), nullptr);
			m_funcTagList->setView(
				m_funcTagListView = new FuncTagSelectList::TreeView(m_funcTagList));
			m_funcTagList->setParent(this);

			m_funcTagListShortView = new FuncTagSelectList::TreeView(m_funcTagList);
			m_funcTagListShortView->setOutputContainer(m_funcTagShortList = new Container);
			m_funcTagShortList->setParent(this);
		}

		~FunctionTagInput() {
			delete m_funcTagList;
			delete m_funcTagListView;
			delete m_funcTagListShortView;
			delete m_funcTagShortList;
		}

		int getSelectedFuncTagCount() {
			return static_cast<int>(getSelectedFunctionTags().size());
		}

		std::list<Function::Tag::Tag*>& getSelectedFunctionTags() {
			return m_funcTagList->getSelectedItems();
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
			renderSelectables();
		}

		void renderSelectables() {
			if (getSelectedFuncTagCount() > 0) {
				std::string info = "Clear (" + toolTip() + ")";
				if (ImGui::Selectable(info.c_str())) {
					getSelectedFunctionTags().clear();
					m_funcTagShortList->clear();
					refresh();
				}
			}

			if (!m_isWinOpen && ImGui::Selectable("More...")) {
				Window::FunctionTagList* win;
				getWindow()->addWindow(
					win = new Window::FunctionTagList(m_funcTagList, "Select function tags")
				);
				win->getCloseEvent() +=
					[&](Events::ISender* sender) {
						m_isWinOpen = false;
					};
				m_isWinOpen = true;
				m_focused = false;
			}
		}

	private:
		FuncTagSelectList* m_funcTagList;
		FuncTagSelectList::TreeView* m_funcTagListView;
		FuncTagSelectList::TreeView* m_funcTagListShortView;
		Container* m_funcTagShortList;
		bool m_isWinOpen = false;
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
			setWidth(450);
			setHeight(300);
			setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar);

			getMainContainer()
				.text("Tag name")
				.addItem(m_nameInput = new Elements::Input::Text)

				.text("Select function parent tag")
				.addItem(m_funcParentTagInput = new Widget::FunctionTagInput(funcManager->getFunctionTagManager()))
				.newLine()

				.text("Select function")
				.addItem(m_funcInput = new Widget::FunctionInput(funcManager))
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
		Widget::FunctionTagInput* m_funcParentTagInput;

		void checkData()
		{
			if (m_funcInput->getSelectedFuncCount() == 0) {
				throw Exception(m_funcInput, "Select a function");
			}

			if (m_funcParentTagInput->getSelectedFuncTagCount() == 0) {
				throw Exception(m_funcParentTagInput, "Select a function tag");
			}

			if (m_nameInput->getInputValue().empty()) {
				throw Exception(m_nameInput, "Type a correct name");
			}
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
					new Elements::Button::ButtonStd("Create", Events::Listener(
						std::function([&](Events::ISender* sender) {
							checkData();
							auto tagManager = m_funcManager->getFunctionTagManager();
							auto func = *m_funcInput->getSelectedFunctions().begin();
							
							tagManager->createTag(
								func->getDeclaration(),
								*m_funcParentTagInput->getSelectedFunctionTags().begin(),
								m_nameInput->getInputValue()
							);
							tagManager->calculateAllTags();
							close();
						})
				)));
		}
	};

	class FunctionTagUpdater
		: public FunctionTagEditor
	{
	public:
		FunctionTagUpdater(CE::FunctionManager* funcManager, API::Function::Function* function, Function::Tag::UserTag* tag)
			: FunctionTagEditor("Function tag editor. Tag: " + tag->getName(), funcManager, function), m_tag(tag)
		{
			m_nameInput->setInputValue(tag->getName());
			m_funcParentTagInput->getSelectedFunctionTags().push_back(tag->getParent());

			getMainContainer()
				.addItem(
					new Elements::Button::ButtonStd("Change", Events::Listener(
						std::function([&](Events::ISender* sender) {
							checkData();

							auto tagManager = m_funcManager->getFunctionTagManager();
							auto func = *m_funcInput->getSelectedFunctions().begin();
							auto parentTag = *m_funcParentTagInput->getSelectedFunctionTags().begin();

							m_tag->setName(m_nameInput->getInputValue());
							m_tag->setParent(parentTag);
							m_tag->setDeclaration(func->getDeclaration());
							tagManager->calculateAllTags();
							close();
					})
				)));
		}

	private:
		Function::Tag::UserTag* m_tag;
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
			TagBtn(Function::Tag::Tag* tag, Events::SpecialEventType::EventHandlerType* eventHandler = nullptr)
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

		FunctionTagShortCut(API::Function::Function* function)
			: m_function(function)
		{
			m_clickOnTag = Events::Listener(
				std::function([&](Events::ISender* sender_) {
					auto sender = static_cast<TagBtn*>(sender_);
					if (!sender->getTag()->isUser())
						return;
					getWindow()->addWindow(
						new Window::FunctionTagUpdater(m_function->getFunctionManager(), m_function, static_cast<Function::Tag::UserTag*>(sender->getTag())));
				})
			);
			m_clickOnTag->setCanBeRemoved(false);

			m_clickOnCreateTag = Events::Listener(
				std::function([&](Events::ISender* sender_) {
					getWindow()->addWindow(new Window::FunctionTagCreator(m_function->getFunctionManager()));
				})
			);
			m_clickOnCreateTag->setCanBeRemoved(false);

			refresh();
		}

		~FunctionTagShortCut() {
			delete m_clickOnTag;
			delete m_clickOnCreateTag;
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

			addItem(new Elements::Button::ButtonTag("+", ColorRGBA(0x0000FFFF), m_clickOnCreateTag));
			newLine();
		}

		Function::Tag::TagCollection getTagCollection() {
			auto tagManager = m_function->getFunctionManager()->getFunctionTagManager();
			return tagManager->getTagCollection(m_function);
		}
	private:
		API::Function::Function* m_function;
		Events::SpecialEventType::EventHandlerType* m_clickOnTag = nullptr;
		Events::SpecialEventType::EventHandlerType* m_clickOnCreateTag = nullptr;
	};

};