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
	class IFunctionList
	{
	public:
		virtual Template::ItemList* getItemList() = 0;
		virtual FunctionEventType::EventHandlerType* getFunctionOpenEvent() = 0;
		virtual void setOpenFunctionEventHandler(FunctionEventType::EventHandlerType* eventHandler) = 0;
		virtual bool checkOnInputValue(API::Function::Function* function, const std::string& value) = 0;
		virtual bool checkAllFilters(API::Function::Function* function) = 0;
	};

	class FunctionList
		: public Template::ItemList,
		public IFunctionList
	{
	public:
		class ListView : public IView
		{
		public:
			class FunctionItem : public Item
			{
			public:
				FunctionItem(API::Function::Function* function, FunctionEventType::EventHandlerType* event)
					: m_function(function)
				{
					auto lamda =
						std::function([&](Events::ISender* sender) {
							if(event != nullptr)
								event->invoke(this, m_function);
						});

					m_signature = new Units::FunctionSignature(m_function,
						nullptr,
						Events::Listener(lamda),
						nullptr
					);
					m_signature->setParent(this);

					beginHeader()
						.addItem(m_signature);

					beginBody()
						.text("Signature: ")
						.sameLine()
						.addItem(m_signature)
						.newLine()
						.newLine()
						.addItem(
							new Elements::Button::ButtonStd(
								"Open control panel",
								Events::Listener(lamda)
							)
						);
				}

				~FunctionItem() {
					m_signature->destroy();
				}
			private:
				//MY TODO: может быть краш при удалении объекта, если он принадлежит нескольким родителям. т.е. битая ссылка. Вроде решил
				Units::FunctionSignature* m_signature;
				API::Function::Function* m_function;
			};

			ListView(IFunctionList* funcList, FunctionManager* funcManager)
				: m_funcList(funcList), m_funcManager(funcManager)
			{}

			int m_maxOutputFunctionCount = 300;
			void onSearch(const std::string& value) override
			{
				getOutContainer()->clear();
				int maxCount = m_maxOutputFunctionCount;

				for (auto& it : m_funcManager->getFunctions()) {
					if (m_funcList->checkOnInputValue(it.second, value) && (!isFilterEnabled() || m_funcList->checkAllFilters(it.second))) {
						getOutContainer()->addItem(createFuncItem(it.second));//MY TODO*: ленивая загрузка, при открытии только
						if (--maxCount == 0)
							break;
					}
				}
			}

			virtual bool isFilterEnabled() {
				return true;
			}

			virtual GUI::Item* createFuncItem(API::Function::Function* function) {
				return new FunctionItem(function, m_funcList->getFunctionOpenEvent());
			}
		protected:
			FunctionManager* m_funcManager;
			IFunctionList* m_funcList;
		};


		class CallStackView : public IView
		{
		public:
			class Node
			{
			public:
				Node(int depth)
					: m_depth(depth)
				{}
				
				int m_depth;
			};

			class GlobalVarNode : public Item, public Node
			{
			public:
				GlobalVarNode(CallGraph::Unit::GlobalVarNode* gVarNode, int depth)
					: m_gVarNode(gVarNode), Node(depth)
				{}

				void render() override {
					std::string str = "Global var node ";
					if (m_gVarNode->getUse() == CallGraph::Unit::GlobalVarNode::Read) {
						str += "(Read)";
					}
					else {
						str += "(Write)";
					}

					if (ImGui::Selectable(str.c_str()))
					{
					}
				}
			private:
				CallGraph::Unit::GlobalVarNode* m_gVarNode;
			};

			class FunctionNode : public Item, public Node
			{
			public:
				FunctionNode(CallGraph::Unit::FunctionNode* funcNode, int depth)
					: m_funcNode(funcNode), Node(depth)
				{}

				void render() override {
					if (ImGui::Selectable("Not calculated function/method"))
					{
					}
				}
			private:
				CallGraph::Unit::FunctionNode* m_funcNode;
			};

			class VMethodNode : public Item, public Node
			{
			public:
				VMethodNode(CallGraph::Unit::VMethodNode* vMethodNode, int depth)
					: m_vMethodNode(vMethodNode), Node(depth)
				{}

				void render() override {
					if (m_vMethodNode->isNotCalculated()) {
						if (ImGui::Selectable("Not calculated virtual method"))
						{
						}
						return;
					}
					if (ImGui::Selectable(m_vMethodNode->getDeclaration()->getSigName().c_str()))
					{
					}
					//DeclSignature
				}
			private:
				CallGraph::Unit::VMethodNode* m_vMethodNode;
			};

			class FunctionBody : public TreeNode, public Node
			{
			public:
				FunctionBody(API::Function::Function* function, int depth, FunctionEventType::EventHandlerType* openFunctionCP)
					: m_function(function), Node(depth), m_openFunctionCP(openFunctionCP)
				{
					addFlags(ImGuiTreeNodeFlags_FramePadding);
				}

				~FunctionBody() {
					if (m_signature != nullptr) {
						m_signature->destroy();
					}
				}

				void onVisibleUpdate() override {}
				
				void renderHeader() override {
					if (m_signature == nullptr) {
						m_signature = new Units::FunctionSignature(
							m_function,
							nullptr,
							Events::Listener(
								std::function([&](Events::ISender* sender) {
									m_openFunctionCP->invoke(this, m_function);
								})
							)
						);
						m_signature->setParent(this);
					}

					ImGui::SameLine();
					m_signature->show();
				}

				CallGraph::Unit::FunctionBody* getBody() {
					return m_function->getBody();
				}

				bool m_isContentLoaded = false;
			private:
				API::Function::Function* m_function;
				Units::FunctionSignature* m_signature = nullptr;
				FunctionEventType::EventHandlerType* m_openFunctionCP;
			};
			
			CallStackView(IFunctionList* funcList, API::Function::Function* function)
				: m_funcList(funcList), m_function(function)
			{
				m_eventVisibleFuncBody = Events::Listener(
					std::function([&](Events::ISender* sender_, Events::VisibleType type) {
						if (type != Events::VisibleOn)
							return;
						auto sender = static_cast<FunctionBody*>(sender_);
						if (!sender->m_isContentLoaded) {
							bool isRemove;
							load(sender, sender->m_depth, isRemove, "");
						}
					})
				);
				m_eventVisibleFuncBody->setCanBeRemoved(false);
			}

			~CallStackView() {
				delete m_eventUpdateCB;
				delete m_eventVisibleFuncBody;
			}

			void onSetView() override {
				m_eventUpdateCB = Events::Listener(
					std::function([&](Events::ISender* sender) {
						m_funcList->getItemList()->update();
					})
				);
				m_eventUpdateCB->setCanBeRemoved(false);

				(*m_funcList->getItemList()->m_underFilterCP)
					.beginReverseInserting()
						.beginContainer()
							.newLine()
							.separator()
							.addItem(m_cb_isFilterEnabled = new Elements::Generic::Checkbox("Use filters and search", false, m_eventUpdateCB))
							.addItem(m_cb_isAlwaysOpen = new Elements::Generic::Checkbox("Open all", true, m_eventUpdateCB))
							.addItem(m_cb_isGlobalVarNode = new Elements::Generic::Checkbox("Global variables", true, m_eventUpdateCB))
							.addItem(m_cb_isVMethodNode = new Elements::Generic::Checkbox("Virtual methods", true, m_eventUpdateCB))
							.addItem(m_cb_isNotCalculatedFunc = new Elements::Generic::Checkbox("Not calculated functions", true, m_eventUpdateCB))
							.addItem(m_cb_isCalculatedFunc = new Elements::Generic::Checkbox("Calculated functions", true, m_eventUpdateCB))
						.end()
					.endReverseInserting();
			}

			//MY TODO*: stack overflow; add check
			void load(FunctionBody* funcBody, int depth, bool& remove, const std::string& funcName) {
				if (isAlwaysOpen() || depth == 1)
					funcBody->setOpen(true);

				int nextDepth = depth + 1;
				remove = true;

				for (auto node : funcBody->getBody()->getNodeList()) {
					if (node->isFunction()) {
						auto funcNode = static_cast<CallGraph::Unit::FunctionNode*>(node);
						if (!funcNode->isNotCalculated()) {
							if (isCalculatedFunc()) {
								FunctionBody* childFuncBody;
								funcBody->addItem(childFuncBody = new FunctionBody(funcNode->getFunction(), nextDepth, m_funcList->getFunctionOpenEvent()));
								if (isAlwaysOpen() || depth == 1) {
									bool isRemove;
									load(childFuncBody, nextDepth, isRemove, funcName);
									if (childFuncBody->empty()) {
										childFuncBody->addFlags(ImGuiTreeNodeFlags_Leaf);
									}

									if (isFilterEnabled()) {
										if (childFuncBody->empty()) {
											if (m_funcList->checkOnInputValue(funcNode->getFunction(), funcName)
												&& m_funcList->checkAllFilters(funcNode->getFunction())) {
												remove = false;
												isRemove = false;
											}
										}

										if (isRemove) {
											funcBody->removeLastItem();
										}
									}
								}
								else {
									funcBody->getVisibleEvent() += m_eventVisibleFuncBody;
								}
							}
						}
						else if (isNotCalculatedFunc()) {
							funcBody->addItem(new FunctionNode(funcNode, nextDepth));
						}
					}
					else if (node->isVMethod() && isVMethodNode()) {
						auto vMethod = static_cast<CallGraph::Unit::VMethodNode*>(node);
						funcBody->addItem(new VMethodNode(vMethod, nextDepth));
					}
					else if (node->isGlobalVar() && isGlobalVarNode()) {
						auto gVar = static_cast<CallGraph::Unit::GlobalVarNode*>(node);
						funcBody->addItem(new GlobalVarNode(gVar, nextDepth));
					}
				}

				funcBody->m_isContentLoaded = true;
			}

			void onSearch(const std::string& funcName) override
			{
				getOutContainer()->clear();
				
				FunctionBody* body;
				getOutContainer()->addItem(body = new FunctionBody(m_function, 1, nullptr));

				bool isRemove;
				load(body, 1, isRemove, funcName);
			}
		private:
			bool isAlwaysOpen() {
				return m_cb_isAlwaysOpen->isSelected() || isFilterEnabled();
			}

			bool isGlobalVarNode() {
				return m_cb_isGlobalVarNode->isSelected() && !isFilterEnabled();
			}

			bool isVMethodNode() {
				return m_cb_isVMethodNode->isSelected() && !isFilterEnabled();
			}

			bool isNotCalculatedFunc() {
				return m_cb_isNotCalculatedFunc->isSelected() && !isFilterEnabled();
			}

			bool isCalculatedFunc() {
				return m_cb_isCalculatedFunc->isSelected() || isFilterEnabled();
			}

			bool isFilterEnabled() {
				return m_cb_isFilterEnabled->isSelected();
			}
		private:
			API::Function::Function* m_function;
			IFunctionList* m_funcList;

			Elements::Generic::Checkbox* m_cb_isFilterEnabled = nullptr;
			Elements::Generic::Checkbox* m_cb_isAlwaysOpen = nullptr;
			Elements::Generic::Checkbox* m_cb_isGlobalVarNode = nullptr;
			Elements::Generic::Checkbox* m_cb_isVMethodNode = nullptr;
			Elements::Generic::Checkbox* m_cb_isNotCalculatedFunc = nullptr;
			Elements::Generic::Checkbox* m_cb_isCalculatedFunc = nullptr;
			Events::SpecialEventType::EventHandlerType* m_eventUpdateCB = nullptr;
			Events::VisibleEventType::EventHandlerType* m_eventVisibleFuncBody;
		};
		friend class CallStackView;


		class FunctionFilter : public Template::FilterManager::Filter
		{
		public:
			FunctionFilter(const std::string& name, FunctionList* functionList)
				: Filter(functionList->getFilterManager(), name), m_functionList(functionList)
			{}

			virtual bool checkFilter(API::Function::Function* function) = 0;

		protected:
			FunctionList* m_functionList;
		};

		class CategoryFilter : public FunctionFilter
		{
		public:
			Elements::List::MultiCombo* m_categoryList = nullptr;

			enum class Category : int
			{
				All					= -1,
				Not					= 0,

				Function			= 1 << 0,
				Method				= 1 << 1,
				StaticMethod		= 1 << 2,
				VirtualMethod		= 1 << 3,
				Constructor			= 1 << 4,
				Destructor			= 1 << 5,
				VirtualDestructor	= 1 << 6,

				Virtual				= VirtualMethod | VirtualDestructor
				
			};

			inline static std::vector<std::pair<std::string, Category>> m_categories = {
				{ std::make_pair("Function", Category::Function) },
				{ std::make_pair("Method", Category::Method) },
				{ std::make_pair("Static method", Category::StaticMethod) },
				{ std::make_pair("Virtual method", Category::VirtualMethod) },
				{ std::make_pair("Constructor", Category::Constructor) },
				{ std::make_pair("Destructor", Category::Destructor) },
				{ std::make_pair("Virtual destructor", Category::VirtualDestructor) },
				{ std::make_pair("Virtual", Category::Virtual) }
			};

			CategoryFilter(FunctionList* functionList)
				: FunctionFilter("Category filter", functionList)
			{
				buildHeader("Filter function by category.");
				beginBody()
					.addItem
					(
						(new Elements::List::MultiCombo("",
							Events::Listener(
								std::function([&](Events::ISender* sender) {
									updateFilter();
								})
							)
						))
						->setWidth(static_cast<float>(functionList->m_styleSettings.m_leftWidth - 10)),
						(Item**)& m_categoryList
					);

				for (auto& cat : m_categories) {
					m_categoryList->addSelectable(cat.first, true);
				}
			}

			void updateFilter() {
				int categorySelected = 0;
				for (int i = 0; i < m_categories.size(); i++) {
					if (m_categoryList->isSelected(i)) {
						categorySelected |= 1 << i;
					}
				}
				m_categorySelected = (Category)categorySelected;
				onChanged();
			}

			bool checkFilter(API::Function::Function* function) override {
				return ((int)m_categorySelected & (int)m_categories[(int)function->getDeclaration()->getFunctionDecl()->getRole()].second) != 0;
			}

			bool isDefined() override {
				return true;
			}

		private:
			Category m_categorySelected = Category::All;
		};

		class ClassFilter : public FunctionFilter
		{
		public:
			ClassFilter(FunctionList* functionList)
				: FunctionFilter("Class filter", functionList)
			{
				buildHeader("Filter function by class.");
				beginBody()
					.text("class settings");
			}

			bool checkFilter(API::Function::Function* function) override {
				if (function->isFunction())
					return false;

				auto method = function->getMethod();
				if (method->getClass()->getId() != m_class->getClass()->getId())
					return false;

				return true;
			}

			bool isDefined() override {
				return m_class != nullptr;
			}

			void setClass(API::Type::Class* Class) {
				m_class = Class;
			}
		private:
			API::Type::Class* m_class = nullptr;
		};

		class FuncTagFilter : public FunctionFilter
		{
		public:
			FuncTagFilter(FunctionList* functionList)
				: FunctionFilter("Function tag filter", functionList)
			{
				buildHeader("Filter function by tag.");
				beginBody()
					.text("tag settings");
			}

			bool checkFilter(API::Function::Function* function) override {
				auto collection = function->getFunctionManager()->getFunctionTagManager()->getTagCollection(function);
				return collection.contains(getTagCollection());
			}

			bool isDefined() override {
				return !m_collection.empty();
			}

			Function::Tag::TagCollection& getTagCollection() {
				return m_collection;
			}
		private:
			Function::Tag::TagCollection m_collection;
		};

		class FunctionFilterCreator : public Template::FilterManager::FilterCreator
		{
		public:
			FunctionFilterCreator(FunctionList* funcList)
				: m_funcList(funcList), FilterCreator(funcList->getFilterManager())
			{
				addItem("Category filter");
				addItem("Class filter");
				addItem("Tag filter");
			}

			Template::FilterManager::Filter* createFilter(int idx) override
			{
				switch (idx)
				{
				case 0: return new CategoryFilter(m_funcList);
				case 1: return new ClassFilter(m_funcList);
				case 2: return new FuncTagFilter(m_funcList);
				}
				return nullptr;
			}

		private:
			FunctionList* m_funcList;
		};

		FunctionList()
			: ItemList(new FunctionFilterCreator(this))
		{
			getFilterManager()->addFilter(new CategoryFilter(this));
			getFilterManager()->addFilter(new ClassFilter(this));
			getFilterManager()->addFilter(new FuncTagFilter(this));
		}

		bool checkOnInputValue(API::Function::Function* function, const std::string& value) override {
			return Generic::String::ToLower(function->getFunction()->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(API::Function::Function* function) override {
			return getFilterManager()->check([&function](Template::FilterManager::Filter* filter) {
				return static_cast<FunctionFilter*>(filter)->checkFilter(function);
			});
		}

		void setOpenFunctionEventHandler(FunctionEventType::EventHandlerType* eventHandler) override {
			m_openFunction = eventHandler;
		}

		Template::ItemList* getItemList() override {
			return this;
		}

		FunctionEventType::EventHandlerType* getFunctionOpenEvent() override {
			return m_openFunction;
		}
	public:
		FunctionEventType::EventHandlerType* m_openFunction;
	};

	class FuncSelectList
		: public Template::SelectableItemList<API::Function::Function>,
		public IFunctionList
	{
	public:
		//MYTODO: сделать фабрику итемов. IFactory, от которого наследуемся 

		class ListView
			: public FunctionList::ListView
		{
		public:
			ListView(FuncSelectList* funcSelectList, FunctionManager* funcManager)
				: m_funcSelectList(funcSelectList), FunctionList::ListView(funcSelectList, funcManager)
			{}

			GUI::Item* createFuncItem(API::Function::Function* function) override {
				auto funcItem = static_cast<FunctionItem*>(FunctionList::ListView::createFuncItem(function));
				makeSelectable(
					funcItem,
					function,
					m_funcSelectList->isItemSelected(function),
					m_funcSelectList->m_eventSelectItem
				);
				return funcItem;
			}
		protected:
			FuncSelectList* m_funcSelectList;
		};

		class ShortView
			: public ListView
		{
		public:
			class FunctionItemWithCheckBox : public Container
			{
			public:
				FunctionItemWithCheckBox(API::Function::Function* function, bool selected, SelectableItemEventType::EventHandlerType* eventSelectFunction)
					: m_function(function), m_eventSelectFunction(eventSelectFunction)
				{
					Elements::Generic::Checkbox* cb;
					(*this)
						.addItem(cb = new Elements::Generic::Checkbox("", selected))
						.sameText(" " + m_function->getFunction()->getSigName());

					cb->getSpecialEvent() += [&](Events::ISender* sender) {
						m_eventSelectFunction->invoke(sender, m_function);
					};
				}

			private:
				API::Function::Function* m_function;
				SelectableItemEventType::EventHandlerType* m_eventSelectFunction;
			};

			ShortView(FuncSelectList* funcSelectList, FunctionManager* funcManager)
				: ListView(funcSelectList, funcManager)
			{}

			bool isFilterEnabled() override {
				return false;
			}

			GUI::Item* createFuncItem(API::Function::Function* function) override {
				return new FunctionItemWithCheckBox(
					function,
					m_funcSelectList->isItemSelected(function),
					m_funcSelectList->m_eventSelectItem
				);
			}
		};

		FuncSelectList(FunctionList* funcList, Events::SpecialEventType::EventHandlerType* eventSelectItemsBtn)
			: Template::SelectableItemList<API::Function::Function>(funcList, eventSelectItemsBtn)
		{}

		FunctionList* getFuncList() {
			return static_cast<FunctionList*>(m_itemList);
		}

		bool checkOnInputValue(API::Function::Function* function, const std::string& value) override {
			return getFuncList()->checkOnInputValue(function, value);
		}

		bool checkAllFilters(API::Function::Function* function) override {
			return getFilterManager()->check([&](Template::FilterManager::Filter* filter) {
				return filter == m_selectedFilter
					? static_cast<SelectedFilter*>(filter)->checkFilter(function)
					: static_cast<FunctionList::FunctionFilter*>(filter)->checkFilter(function);
			});
		}

		void setOpenFunctionEventHandler(FunctionEventType::EventHandlerType* eventHandler) override {
			getFuncList()->setOpenFunctionEventHandler(eventHandler);
		}

		Template::ItemList* getItemList() override {
			return this;
		}

		FunctionEventType::EventHandlerType* getFunctionOpenEvent() override {
			return getFuncList()->getFunctionOpenEvent();
		}
	};
};

namespace GUI::Window
{
	class FunctionList : public IWindow
	{
	public:
		FunctionList(Widget::IFunctionList* funcList, const std::string& name = "Function list")
			: m_funcList(funcList), IWindow(name)
		{
			//MY TODO*: error
			m_openFunctionCP = Events::Listener(
				std::function([&](Events::ISender* sender, API::Function::Function* function) {
					getParent()->getMainContainer().clear();
					getParent()->getMainContainer().addItem(new Widget::FunctionCP(function));
				})
			);
			m_openFunctionCP->setCanBeRemoved(false);

			funcList->setOpenFunctionEventHandler(m_openFunctionCP);
			setMainContainer(funcList->getItemList());
		}

		~FunctionList() {
			delete m_openFunctionCP;
		}

		Widget::IFunctionList* getList() {
			return m_funcList;
		}
	private:
		Widget::FunctionEventType::EventHandlerType* m_openFunctionCP;
		Widget::IFunctionList* m_funcList;
	};
};

namespace GUI::Widget
{
	class FunctionInput : public Template::ItemInput
	{
	public:
		FunctionInput(FunctionManager* funcManager)
		{
			m_funcSelectList = new FuncSelectList(new FunctionList, nullptr);
			m_funcSelectList->setView(
				m_funcListView = new FuncSelectList::ListView(m_funcSelectList, funcManager));
			m_funcSelectList->setParent(this);
			
			m_funcListShortView = new FuncSelectList::ShortView(m_funcSelectList, funcManager);
			m_funcListShortView->setOutputContainer(m_funcShortList = new Container);
			m_funcShortList->setParent(this);
			m_funcListShortView->m_maxOutputFunctionCount = 15;
		}

		~FunctionInput() {
			m_funcSelectList->destroy();
			m_funcShortList->destroy();
			delete m_funcListView;
			delete m_funcListShortView;
		}

		int getSelectedFuncCount() {
			return static_cast<int>(getSelectedFunctions().size());
		}

		std::list<API::Function::Function*>& getSelectedFunctions() {
			return m_funcSelectList->getSelectedItems();
		}
	protected:
		std::string getPlaceHolder() override {
			if (getSelectedFuncCount() == 0)
				return "No selected function(s)";
			
			std::string info = "";
			int max = 2;
			for (auto func : getSelectedFunctions()) {
				info += func->getFunction()->getName() + ",";
				if (--max == 0) break;
			}
			
			if (getSelectedFuncCount() > 2) {
				info += " ...";
			}
			else {
				info.pop_back();
			}

			return info.data();
		}

		std::string toolTip() override {
			if (getSelectedFuncCount() == 0)
				return "please, select one or more functions";
			return "selected "+ std::to_string(getSelectedFuncCount()) +" functions";
		}

		void onSearch(const std::string& text) {
			m_funcListShortView->onSearch(text);
		}

		void renderShortView() override {
			m_funcShortList->show();
			renderSelectables();
		}

		void renderSelectables() {
			if (getSelectedFuncCount() > 0) {
				std::string info = "Clear ("+ toolTip() +")";
				if (ImGui::Selectable(info.c_str())) {
					getSelectedFunctions().clear();
					m_funcShortList->clear();
					refresh();
				}
			}

			if (!m_isWinOpen && ImGui::Selectable("More...")) {
				Window::FunctionList* win;
				getWindow()->addWindow(
					win = new Window::FunctionList(m_funcSelectList, "Select functions")
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
		FuncSelectList* m_funcSelectList;
		FuncSelectList::ListView* m_funcListView;
		FuncSelectList::ShortView* m_funcListShortView;
		Container* m_funcShortList;
		bool m_isWinOpen = false;
	};
};