#pragma once
#include "FunctionList.h"
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include <Manager/TriggerManager.h>
#include <GUI/Windows/Window.h>

using namespace CE;

/*
	MYTODO: сделать окно редактирования триггера: разные блоки обновления
	MYTODO: сделать окно редактирования фильтров через наследование
	MYTODO: сделать редактирование фильтров в items.h, сделать интерфейс-элемент(getName(), onClickEvent, )
	MYTODO: отображать при выборе списка функций в редакторе триггера у каждой функции состояние хука
*/

namespace GUI::Widget
{
	using TriggerEventType = Events::Event<Events::ISender*, Trigger::ITrigger*>;

	
	class ITriggerList
	{
	public:
		virtual Template::ItemList* getItemList() = 0;
		virtual TriggerEventType::EventHandlerType* getEventHandlerClickOnName() = 0;
		virtual void setEventHandlerClickOnName(TriggerEventType::EventHandlerType* eventHandler) = 0;
		virtual bool checkOnInputValue(Trigger::ITrigger* trigger, const std::string& value) = 0;
		virtual bool checkAllFilters(Trigger::ITrigger* type) = 0;
	};


	class TriggerList
		: public Template::ItemList,
		public ITriggerList
	{
	public:
		class ListView : public IView
		{
		public:
			class TriggerItem : public Item
			{
			public:
				TriggerItem(Trigger::ITrigger* trigger, TriggerEventType::EventHandlerType* eventClickOnName)
					: m_trigger(trigger), m_eventClickOnName(eventClickOnName)
				{
					addFlags(ImGuiTreeNodeFlags_Leaf, true);

					auto text = new Elements::Text::ClickedText(trigger->getName());
					beginHeader()
						.addItem(text);
					text->getLeftMouseClickEvent() +=
						[=](Events::ISender* sender) {
							if(eventClickOnName != nullptr)
								eventClickOnName->invoke(this, trigger);
						};
				}

			private:
				Trigger::ITrigger* m_trigger;
				TriggerEventType::EventHandlerType* m_eventClickOnName;
			};

			ListView(ITriggerList* triggerList, TriggerManager* triggerManager)
				: m_triggerList(triggerList), m_triggerManager(triggerManager)
			{}

			int m_maxOutputTriggerCount = 300;
			void onSearch(const std::string& value) override
			{
				getOutContainer()->clear();
				int maxCount = m_maxOutputTriggerCount;

				for (auto& it : m_triggerManager->getTriggers()) {
					if (m_triggerList->checkOnInputValue(it.second, value) && m_triggerList->checkAllFilters(it.second)) {
						getOutContainer()->addItem(createItem(it.second));
						if (--maxCount == 0)
							break;
					}
				}
			}

			virtual GUI::Item* createItem(Trigger::ITrigger* trigger) {
				return new TriggerItem(trigger, m_triggerList->getEventHandlerClickOnName());
			}
		protected:
			TriggerManager* m_triggerManager;
			ITriggerList* m_triggerList;
		};
		friend class ListView;

		class TriggerFilter : public Template::FilterManager::Filter
		{
		public:
			TriggerFilter(const std::string& name, TriggerList* triggerList)
				: Filter(triggerList->getFilterManager(), name), m_triggerList(triggerList)
			{}

			virtual bool checkFilter(Trigger::ITrigger* type) = 0;
		protected:
			TriggerList* m_triggerList;
		};

		class TypeFilterCreator : public Template::FilterManager::FilterCreator
		{
		public:
			TypeFilterCreator(TriggerList* triggerList)
				: m_triggerList(triggerList), FilterCreator(triggerList->getFilterManager())
			{}

			Template::FilterManager::Filter* createFilter(int idx) override
			{
				return nullptr;
			}

		private:
			TriggerList* m_triggerList;
		};

		TriggerList()
			: ItemList(new TypeFilterCreator(this))
		{
			
		}

		bool checkOnInputValue(Trigger::ITrigger* trigger, const std::string& value) override {
			return Generic::String::ToLower(trigger->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(Trigger::ITrigger* type) override {
			return getFilterManager()->check([&type](Template::FilterManager::Filter* filter) {
				return static_cast<TriggerFilter*>(filter)->checkFilter(type);
			});
		}

		TriggerEventType::EventHandlerType* getEventHandlerClickOnName() override {
			return m_eventClickOnName;
		}
		
		void setEventHandlerClickOnName(TriggerEventType::EventHandlerType* eventHandler) override {
			m_eventClickOnName = eventHandler;
		}

		Template::ItemList* getItemList() override {
			return this;
		}
	private:
		TriggerEventType::EventHandlerType* m_eventClickOnName = nullptr;
	};




	class TriggerSelectList
		: public Template::SelectableItemList<Trigger::ITrigger>,
		public ITriggerList
	{
	public:
		class ListView
			: public TriggerList::ListView
		{
		public:
			ListView(TriggerSelectList* triggerSelectList, TriggerManager* triggerManager)
				: m_triggerSelectList(triggerSelectList), TriggerList::ListView(triggerSelectList, triggerManager)
			{}

			GUI::Item* createItem(Trigger::ITrigger* trigger) override {
				auto triggerItem = static_cast<TriggerItem*>(TriggerList::ListView::createItem(trigger));
				makeSelectable(
					triggerItem,
					trigger,
					m_triggerSelectList->isItemSelected(trigger),
					m_triggerSelectList->m_eventSelectItem
				);
				return triggerItem;
			}
		protected:
			TriggerSelectList* m_triggerSelectList;
		};

		TriggerSelectList(TriggerList* triggerList, Events::SpecialEventType::EventHandlerType* eventSelectItems)
			: Template::SelectableItemList<Trigger::ITrigger>(triggerList, eventSelectItems)
		{}

		TriggerList* getTriggerList() {
			return static_cast<TriggerList*>(m_itemList);
		}

		bool checkOnInputValue(Trigger::ITrigger* trigger, const std::string& value) override {
			return getTriggerList()->checkOnInputValue(trigger, value);
		}

		bool checkAllFilters(Trigger::ITrigger* trigger) override {
			return getFilterManager()->check([&](Template::FilterManager::Filter* filter) {
				return filter == m_selectedFilter
					? static_cast<SelectedFilter*>(filter)->checkFilter(trigger)
					: false;//static_cast<TriggerList::FunctionFilter*>(filter)->checkFilter(trigger);
			});
		}

		TriggerEventType::EventHandlerType* getEventHandlerClickOnName() override {
			return getTriggerList()->getEventHandlerClickOnName();
		}

		void setEventHandlerClickOnName(TriggerEventType::EventHandlerType* eventHandler) override {
			getTriggerList()->setEventHandlerClickOnName(eventHandler);
		}

		Template::ItemList* getItemList() override {
			return this;
		}
	};
};

namespace GUI::Window
{
	class TriggerList : public IWindow
	{
	public:
		TriggerList(Widget::ITriggerList* triggerList = new Widget::TriggerList, const std::string& name = "Trigger list")
			: m_triggerList(triggerList), IWindow(name)
		{
			setMainContainer(m_triggerList->getItemList());
		}

		~TriggerList() {
			delete m_openFunctionCP;
		}

		Widget::ITriggerList* getList() {
			return m_triggerList;
		}
	private:
		Events::SpecialEventType::EventHandlerType* m_openFunctionCP;
		Widget::ITriggerList* m_triggerList;
	};
};



namespace GUI::Widget
{
	class TriggerInput : public Template::ItemInput
	{
	public:
		TriggerInput(TriggerManager* triggerManager)
		{
			m_triggerSelectList = new TriggerSelectList(new TriggerList, nullptr);
			m_triggerSelectList->setView(
				m_triggerListView = new TriggerSelectList::ListView(m_triggerSelectList, triggerManager));
			m_triggerSelectList->setParent(this);

			m_triggerListShortView = new TriggerSelectList::ListView(m_triggerSelectList, triggerManager);
			m_triggerListShortView->setOutputContainer(m_triggerShortList = new Container);
			m_triggerShortList->setParent(this);
			m_triggerListShortView->m_maxOutputTriggerCount = 15;
		}

		~TriggerInput() {
			m_triggerSelectList->destroy();
			m_triggerShortList->destroy();
			delete m_triggerListView;
			delete m_triggerListShortView;
		}

		int getSelectedTriggerCount() {
			return static_cast<int>(getSelectedTriggers().size());
		}

		std::list<Trigger::ITrigger*>& getSelectedTriggers() {
			return m_triggerSelectList->getSelectedItems();
		}
	protected:
		std::string getPlaceHolder() override {
			if (getSelectedTriggerCount() == 0)
				return "No selected trigger(s)";

			std::string info = "";
			int max = 2;
			for (auto trigger : getSelectedTriggers()) {
				info += trigger->getName() + ",";
				if (--max == 0) break;
			}

			if (getSelectedTriggerCount() > 2) {
				info += " ...";
			}
			else {
				info.pop_back();
			}

			return info.data();
		}

		std::string toolTip() override {
			if (getSelectedTriggerCount() == 0)
				return "please, select one or more triggers";
			return "selected " + std::to_string(getSelectedTriggerCount()) + " triggers";
		}

		void onSearch(const std::string& text) {
			m_triggerListShortView->onSearch(text);
		}

		void renderShortView() override {
			m_triggerShortList->show();
			renderSelectables();
		}

		void renderSelectables() {
			if (getSelectedTriggerCount() > 0) {
				std::string info = "Clear (" + toolTip() + ")";
				if (ImGui::Selectable(info.c_str())) {
					getSelectedTriggers().clear();
					m_triggerShortList->clear();
					refresh();
				}
			}

			if (!m_isWinOpen && ImGui::Selectable("More...")) {
				Window::TriggerList* win;
				getWindow()->addWindow(
					win = new Window::TriggerList(m_triggerSelectList, "Select triggers")
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
		TriggerSelectList* m_triggerSelectList;
		TriggerSelectList::ListView* m_triggerListView;
		TriggerSelectList::ListView* m_triggerListShortView;
		Container* m_triggerShortList;
		bool m_isWinOpen = false;
	};
};

namespace TriggerFilterInfo {
	struct TreeNode {
		std::string m_name;
		std::string m_desc;

		TreeNode(const std::string& name, const std::string& desc)
			: m_name(name), m_desc(desc)
		{}

		virtual ~TreeNode() {}
	};

	struct Category : public TreeNode {
		std::list<TreeNode*> m_nodes;

		Category(const std::string& name, const std::string& desc, std::list<TreeNode*> nodes = {})
			: TreeNode(name, desc), m_nodes(nodes)
		{}
	};

	template<class T1, typename T2>
	static T1* GetFilter_(T2 id, TreeNode* node) {
		if (T1* filter = dynamic_cast<T1*>(node)) {
			if (filter->m_id == id)
				return filter;
		}
		if (Category* category = dynamic_cast<Category*>(node)) {
			for (auto it : category->m_nodes) {
				if (T1* filter = GetFilter_<T1, T2>(id, it)) {
					return filter;
				}
			}
		}
		return nullptr;
	}

	namespace Function
	{
		using namespace Trigger::Function::Filter;

		struct Filter : public TreeNode {
			Id m_id;
			std::function<IFilter * ()> m_createFilter;

			Filter(Id id, const std::function<IFilter * ()>& createFilter, const std::string& name, const std::string& desc = "")
				: m_id(id), m_createFilter(createFilter), TreeNode(name, desc)
			{}
		};
		
		static inline Category* RootCategory =
			new Category("Filters", "", {
				new Category("Condition", "", {
					new Filter(Id::Condition_AND, []() { return new ConditionFilter(Id::Condition_AND); }, "AND"),
					new Filter(Id::Condition_OR, []() { return new ConditionFilter(Id::Condition_OR); }, "OR"),
					new Filter(Id::Condition_XOR, []() { return new ConditionFilter(Id::Condition_XOR); }, "XOR"),
					new Filter(Id::Condition_NOT, []() { return new ConditionFilter(Id::Condition_NOT); }, "NOT")
				}),
				new Filter(Id::Empty, []() { return new Empty; }, "Empty"),
				new Filter(Id::Object, []() { return new Object; }, "Object"),
				new Filter(Id::Argument, []() { return new Cmp::Argument; }, "Argument"),
				new Filter(Id::ReturnValue, []() { return new Cmp::RetValue; }, "Return value")
			});

		static Filter* GetFilter(Id id) {
			return GetFilter_<Filter>(id, RootCategory);
		}
	};
};


#include <GUI/AddressInput.h>
namespace GUI::Widget
{
	namespace FunctionTriggerFilter
	{
		using namespace Trigger::Function::Filter;

		class FilterEditor : public Container {
		public:
			FilterEditor(Trigger::Function::Trigger* trigger, TriggerFilterInfo::Function::Filter* info)
				: m_trigger(trigger), m_filterInfo(info)
			{
				text("Trigger: " + trigger->getName());
				text("Filter: " + m_filterInfo->m_name);
				text("Description:\n" + m_filterInfo->m_desc);
				newLine();
				newLine();
			}

			virtual void save() {};
		protected:
			Trigger::Function::Trigger* m_trigger;
			TriggerFilterInfo::Function::Filter* m_filterInfo;
		};

		class ObjectEditor : public FilterEditor {
		public:
			ObjectEditor(Object* filter, Trigger::Function::Trigger* trigger, TriggerFilterInfo::Function::Filter* info)
				: m_filter(filter), FilterEditor(trigger, info)
			{
				text("Enter the address of the object.");
				addItem(m_valueInput = new AddressInput);
				m_valueInput->setAddress(filter->m_addr);
			}

			void save() override {
				m_filter->m_addr = m_valueInput->getAddress();
			}
		private:
			Object* m_filter;
			AddressInput* m_valueInput;
		};

		namespace Compare
		{
			class OperationSelector : public Elements::List::Combo
			{
			public:
				OperationSelector(Cmp::Operation operation = Cmp::Operation::Eq)
					: Elements::List::Combo("Operation", static_cast<int>(operation))
				{
					addItem("Equal (==)");
					addItem("Not equal (!=)");
					addItem("Less than (<)");
					addItem("Less or equal (<=)");
					addItem("Greater than (>=)");
					addItem("Greater or equal (>)");
				}

				Cmp::Operation getOperation() {
					return static_cast<Cmp::Operation>(getSelectedItem());
				}
			};

			class ArgumentEditor : public FilterEditor {
			public:
				ArgumentEditor(Cmp::Argument* filter, Trigger::Function::Trigger* trigger, TriggerFilterInfo::Function::Filter* info, CE::TypeManager* typeManager)
					: m_filter(filter), FilterEditor(trigger, info)
				{
					text("Select an argument index.");
					addItem(m_argIndexInput = new Elements::Input::Int);
					m_argIndexInput->setInputValue(m_filter->m_argId);
					m_argIndexInput->getSpecialEvent() += [=](Events::ISender* sender) {
						update();
					};
					newLine();

					text("Select an operation.");
					addItem(m_operationInput = new OperationSelector(m_filter->m_operation));
					newLine();

					text("Enter a value.");
					addItem(m_valueInput = new IntegralValueInput(m_filter->m_value, getType(0)));
					newLine();
					

					m_valueInput->getAddressValueEditor()->setTypeManager(typeManager);
				}

			private:
				void update() {
					auto argIdx = m_argIndexInput->getInputValue() - 1;
					if (argIdx < 0)
						return;
					m_valueInput->changeType(getType(argIdx));
				}

				CE::Type::Type* getType(int argIdx) {
					if (m_trigger->getHooks().size() == 0)
						return new CE::Type::UInt64;
					
					auto hook = *m_trigger->getHooks().begin();
					auto argList = hook->getFunctionDef()->getDeclaration().getSignature().getArgList();
					if (argIdx >= argList.size() || argIdx < 0)
						return new CE::Type::UInt64;

					return argList[argIdx];
				}

			public:
				void save() override {
					m_filter->m_argId = m_argIndexInput->getInputValue();
					m_filter->m_operation = m_operationInput->getOperation();
					m_filter->m_value = m_valueInput->getValue();
				}
			private:
				Cmp::Argument* m_filter;
				Elements::Input::Int* m_argIndexInput;
				OperationSelector* m_operationInput;
				IntegralValueInput* m_valueInput;
			};

			class RetValueEditor : public FilterEditor {
			public:
				RetValueEditor(Cmp::RetValue* filter, Trigger::Function::Trigger* trigger, TriggerFilterInfo::Function::Filter* info)
					: m_filter(filter), FilterEditor(trigger, info)
				{

				}

			private:
				Cmp::RetValue* m_filter;
				AddressInput* m_valueInput;
			};
		};
	};
};


namespace GUI::Window
{
	

	class GenericTriggerEditor
		: public PrjWindow
	{
	public:
		GenericTriggerEditor(const std::string& name, Trigger::ITrigger* trigger)
			: PrjWindow(name), m_trigger(trigger)
		{
			setFlags(ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar);

			getMainContainer()
				.text("Trigger name")
				.addItem(m_nameInput = new Elements::Input::Text);
		}

	protected:
		Trigger::ITrigger* m_trigger;
		Elements::Input::Text* m_nameInput;
	};

	namespace FunctionTrigger {
		using namespace Trigger::Function::Filter;

		class FilterWinEditor : public PrjWindow
		{
		public:
			FilterWinEditor(Trigger::Function::Trigger* trigger, IFilter* filter, TriggerFilterInfo::Function::Filter* info)
				: PrjWindow("Fitler editor: " + info->m_name)
			{
				setWidth(450);
				setHeight(300);

				auto filterEditor = createFilterEditor(trigger, filter, info);
				(*filterEditor)
					.newLine()
					.addItem(
						new Elements::Button::ButtonStd(
							"Ok",
							Events::Listener(
								std::function([=](Events::ISender* sender) {
									filterEditor->save();
									sendCloseEvent();
								})
							)
						)
					);
				setMainContainer(filterEditor);
			}

			Widget::FunctionTriggerFilter::FilterEditor* createFilterEditor(Trigger::Function::Trigger* trigger, IFilter* filter, TriggerFilterInfo::Function::Filter* info) {
				using namespace Widget::FunctionTriggerFilter;

				switch (filter->getId())
				{
				case Trigger::Function::Filter::Id::Object:
					return new ObjectEditor(static_cast<Object*>(filter), trigger, info);
				case Trigger::Function::Filter::Id::Argument:
					return new Compare::ArgumentEditor(static_cast<Cmp::Argument*>(filter), trigger, info, getProject()->getProgramExe()->getTypeManager());
				case Trigger::Function::Filter::Id::ReturnValue:
					return new Compare::RetValueEditor(static_cast<Cmp::RetValue*>(filter), trigger, info);
				}
				return new FilterEditor(trigger, info);
			}
		};

		class TriggerEditor
			: public GenericTriggerEditor
		{
		public:
			class FilterList : public Elements::Input::ObjectList {
			public:
				class Filter : public IObject {
				public:
					Filter(IFilter* filter, TriggerFilterInfo::Function::Filter* filterInfo)
						: m_filter(filter), m_filterInfo(filterInfo)
					{}

					std::string getStatusName() override {
						return m_filterInfo->m_name;
					}

					IFilter* getFilter() {
						return m_filter;
					}
				private:
					IFilter* m_filter;
					TriggerFilterInfo::Function::Filter* m_filterInfo;
				};

				class CompositeFilter : public Elements::Input::ObjectList {
				public:
					CompositeFilter(ICompositeFilter* compositeFilter, TriggerFilterInfo::Function::Filter* filterInfo)
						: m_compositeFilter(compositeFilter), m_filterInfo(filterInfo)
					{}

					std::string getStatusName() override {
						return m_filterInfo->m_name;
					}

					ICompositeFilter* getFilter() {
						return m_compositeFilter;
					}
				private:
					ICompositeFilter* m_compositeFilter;
					TriggerFilterInfo::Function::Filter* m_filterInfo;
				};

				using TreeView = Elements::List::TreeView<Trigger::Function::Filter::Id>;

				FilterList(Trigger::Function::Trigger* trigger, TriggerEditor* triggerEditor)
					: m_trigger(trigger), m_triggerEditor(triggerEditor)
				{
					for (auto filter : trigger->getFilters()->getFilters()) {
						addObject(new Filter(filter, TriggerFilterInfo::Function::GetFilter(filter->getId())));
					}

					m_treeView = new TreeView;
					m_treeView->setParent(this);
					generateTreeView(m_treeView->getRoot());

					m_editObjectEvent += [&](IObject* object) {
						auto filter = static_cast<Filter*>(object);
						auto filterInfo = TriggerFilterInfo::Function::GetFilter(filter->getFilter()->getId());
						
						if (filterInfo != nullptr) {
							m_triggerEditor->showFilterWinEditor(filter->getFilter(), filterInfo);
						}
					};

					m_removeObjectEvent += [&](IObject* object) {
						if (m_triggerEditor->m_winEditor != nullptr) {
							throw Exception("Close window filter editor to remove.");
						}

						auto filter = static_cast<Filter*>(object);
						m_trigger->getFilters()->removeFilter(filter->getFilter());
						delete filter->getFilter();
					};

					m_treeView->getTreeNodeSelectedEvent() += [&](TreeView::TreeNode* treeNode) {
						auto filterInfo = TriggerFilterInfo::Function::GetFilter(treeNode->getValue());
						
						if (filterInfo != nullptr) {
							auto filter = filterInfo->m_createFilter();
							addObject(new Filter(filter, filterInfo));
							m_triggerEditor->showFilterWinEditor(filter, filterInfo);
						}
					};
				}

				~FilterList() {
					m_treeView->destroy();
				}

				void generateTreeView(TreeView::TreeNode* parentTreeNode, TriggerFilterInfo::TreeNode* node = TriggerFilterInfo::Function::RootCategory) {
					using namespace TriggerFilterInfo;

					TreeView::TreeNode* treeNode = new TreeView::TreeNode(node->m_name, node->m_desc);
					parentTreeNode->addNode(treeNode);

					if (auto filter = dynamic_cast<TriggerFilterInfo::Function::Filter*>(node)) {
						treeNode->setValue(filter->m_id);
					}

					if (Category* category = dynamic_cast<Category*>(node)) {
						for (auto it : category->m_nodes) {
							generateTreeView(treeNode, it);
						}
					}
				}

				void render() override {
					Elements::Input::ObjectList::render();
					
					if (ImGui::Button("Add")) {
						ImGui::OpenPopup("FilterListCreator");
					}

					if (ImGui::BeginPopup("FilterListCreator"))
					{
						m_treeView->show();
						ImGui::EndPopup();
					}
				}

			private:
				Trigger::Function::Trigger* m_trigger;
				TreeView* m_treeView;
				TriggerEditor* m_triggerEditor;
			};
			friend class FilterList;

			TriggerEditor(Trigger::Function::Trigger* trigger, CE::FunctionManager* funcManager)
				: GenericTriggerEditor("Function trigger editor", trigger)
			{
				setWidth(450);
				setHeight(300);

				getMainContainer()
					.text("Select function(s)")
					.addItem(m_funcInput = new Widget::FunctionInput(funcManager))
					.newLine()
					.newLine()
					.text("Filter list")
					.addItem(m_filterList = new FilterList(trigger, this))
					.newLine();
			}

			Trigger::Function::Trigger* getTrigger() {
				return static_cast<Trigger::Function::Trigger*>(m_trigger);
			}

			void showFilterWinEditor(IFilter* filter, TriggerFilterInfo::Function::Filter* filterInfo) {
				if (m_winEditor != nullptr) {
					m_winEditor->close();
				}
				m_winEditor = new FilterWinEditor(getTrigger(), filter, filterInfo);
				addWindow(m_winEditor);

				m_winEditor->getCloseEvent() +=
					[&](Events::ISender* sender) {
					m_winEditor = nullptr;
				};
			}
		private:
			Widget::FunctionInput* m_funcInput;
			FilterList* m_filterList;
			FilterWinEditor* m_winEditor = nullptr;
		};
	};
};