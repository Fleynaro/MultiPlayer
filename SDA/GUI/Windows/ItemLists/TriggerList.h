#pragma once
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include <Manager/TriggerManager.h>
#include "../ProjectWindow.h"

using namespace CE;

namespace GUI::Widget
{
	class ITriggerList
	{
	public:
		virtual Template::ItemList* getItemList() = 0;
		virtual Events::Event* getEventHandlerClickOnName() = 0;
		virtual void setEventHandlerClickOnName(Events::Event* eventHandler) = 0;
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
				TriggerItem(Trigger::ITrigger* trigger, Events::Event* eventClickOnName)
					: m_trigger(trigger)
				{
					addFlags(ImGuiTreeNodeFlags_Leaf, true);

					auto text = new Elements::Text::ClickedText(trigger->getName());
					beginHeader()
						.addItem(text);
					text->getLeftMouseClickEvent() += eventClickOnName;
				}

			private:
				Trigger::ITrigger* m_trigger;
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
				auto eventHandler = new Events::EventHook(m_triggerList->getEventHandlerClickOnName(), trigger);
				return new TriggerItem(trigger, eventHandler);
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

		Events::Event* getEventHandlerClickOnName() override {
			return m_eventClickOnName;
		}
		
		void setEventHandlerClickOnName(Events::Event* eventHandler) override {
			m_eventClickOnName = eventHandler;
		}

		Template::ItemList* getItemList() override {
			return this;
		}
	private:
		Events::Event* m_eventClickOnName = nullptr;
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
				return new SelectableItem(
					static_cast<TriggerItem*>(TriggerList::ListView::createItem(trigger)),
					m_triggerSelectList->isItemSelected(trigger),
					new Events::EventHook(m_triggerSelectList->m_eventSelectItem, trigger)
				);
			}
		protected:
			TriggerSelectList* m_triggerSelectList;
		};

		TriggerSelectList(TriggerList* triggerList, Events::Event* eventSelectItems)
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

		Events::Event* getEventHandlerClickOnName() override {
			return getTriggerList()->getEventHandlerClickOnName();
		}

		void setEventHandlerClickOnName(Events::Event* eventHandler) override {
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
		Events::EventHandler* m_openFunctionCP;
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
			return getSelectedTriggers().size();
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
					new Events::EventUI(
						EVENT_LAMBDA(info) {
					m_isWinOpen = false;
				}
				);
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


//namespace GUI::Widget
//{
//	class TriggerInput : public Template::ItemInput
//	{
//	public:
//		TriggerInput(TriggerManager* triggerManager)
//			: m_selectDataType(this)
//		{
//			m_triggerList = new TriggerList;
//
//			m_triggerList->setView(
//				m_triggerListView = new TriggerList::ListView(m_triggerList, triggerManager)
//			);
//			m_triggerList->setParent(this);
//
//			m_triggerShortListView = new TriggerList::ListView(m_triggerList, triggerManager);
//			m_triggerShortListView->setOutputContainer(m_triggerShortList = new Container);
//			m_triggerShortList->setParent(this);
//			m_triggerShortListView->m_maxOutputTriggerCount = 20;
//
//
//			m_selectDataTypeEvent = new Events::EventUI(EVENT_LAMBDA(info) {
//				auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
//				auto trigger = (Trigger::ITrigger*)message->getUserDataPtr();
//
//				m_selectedType = trigger->getType();
//				m_focused = false;
//				m_selectDataType.callEventHandler();
//			});
//			m_selectDataTypeEvent->setCanBeRemoved(false);
//			m_triggerList->setEventHandlerClickOnName(m_selectDataTypeEvent);
//		}
//
//		~TriggerInput() {
//			m_triggerList->destroy();
//			m_triggerShortList->destroy();
//			delete m_triggerListView;
//			delete m_triggerShortListView;
//			delete m_selectDataTypeEvent;
//		}
//
//		void setSelectedType(CE::Type::Type* selectedType) {
//			m_selectedType = selectedType;
//		}
//
//		CE::Type::Type* getSelectedType() {
//			return m_selectedType;
//		}
//
//		bool isTypeSelected() {
//			return m_selectedType != nullptr;
//		}
//
//		Events::Messager m_selectDataType;
//	protected:
//		std::string getPlaceHolder() override {
//			if (!isTypeSelected())
//				return "No selected type";
//			return getSelectedType()->getDisplayName();
//		}
//
//		std::string toolTip() override {
//			if (!isTypeSelected())
//				return "please, select a type";
//			return "type selected";
//		}
//
//		void onSearch(const std::string& text) {
//			m_triggerShortListView->onSearch(text);
//		}
//
//		void renderShortView() override {
//			m_triggerShortList->show();
//			renderSelectables();
//		}
//
//		void renderSelectables() {
//			if (isTypeSelected()) {
//				if (ImGui::Selectable("Clear")) {
//					m_selectedType = nullptr;
//				}
//			}
//
//			if (!m_isWinOpen && ImGui::Selectable("More...")) {
//				Window::TriggerList* win;
//				getWindow()->addWindow(
//					win = new Window::TriggerList(m_triggerList)
//				);
//				win->getCloseEvent() +=
//					new Events::EventUI(
//						EVENT_LAMBDA(info) {
//					m_isWinOpen = false;
//				}
//				);
//				m_isWinOpen = true;
//				m_focused = false;
//			}
//		}
//
//	private:
//		TriggerList* m_triggerList;
//		TriggerList::ListView* m_triggerListView;
//		TriggerList::ListView* m_triggerShortListView;
//		Container* m_triggerShortList;
//		CE::Type::Type* m_selectedType = nullptr;
//		bool m_isWinOpen = false;
//		Events::EventHandler* m_selectDataTypeEvent;
//	};
//};