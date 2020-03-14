#pragma once
#include "FunctionList.h"
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include <Manager/TriggerManager.h>
#include "../ProjectWindow.h"

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

namespace GUI::Window
{
	class TriggerEditor
		: public IWindow
	{
	public:
		TriggerEditor(const std::string& name, Trigger::ITrigger* trigger)
			: IWindow(name), m_trigger(trigger)
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

	class FunctionTriggerEditor
		: public TriggerEditor
	{
	public:
		class FilterList : public Elements::Input::ObjectList {
		public:
			class Filter : public IObject {
			public:
				Filter(Trigger::Function::Filter::IFilter* filter)
				{}

				std::string getStatusName() override {
					return std::to_string((int)m_filter->getId());
				}

				bool isObjectList() override {
					return false;
				}
			private:
				Trigger::Function::Filter::IFilter* m_filter;
			};

			FilterList(Trigger::Function::Trigger* trigger)
				: m_trigger(trigger)
			{
				for (auto filter : trigger->getFilters()) {
					addObject(new Filter(filter));
				}

				m_editObjectEvent += [&](IObject* object) {
					auto filter = static_cast<Filter*>(object);
					if (filter == nullptr) {

						return;
					}


				};
			}

		private:
			Trigger::Function::Trigger* m_trigger;
		};

		FunctionTriggerEditor(Trigger::Function::Trigger* trigger, CE::FunctionManager* funcManager)
			: TriggerEditor("Function trigger editor", trigger)
		{
			setWidth(450);
			setHeight(300);

			getMainContainer()
				.text("Select function(s)")
				.addItem(m_funcInput = new Widget::FunctionInput(funcManager))
				.newLine()
				.newLine()
				.text("Filter list")
				.addItem(m_filterList = new FilterList(trigger))
				.newLine();
		}

		Trigger::Function::Trigger* getTrigger() {
			return static_cast<Trigger::Function::Trigger*>(m_trigger);
		}

	private:
		Widget::FunctionInput* m_funcInput;
		FilterList* m_filterList;
	};
};