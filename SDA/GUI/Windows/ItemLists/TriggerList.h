#pragma once
#include "Shared/GUI/Widgets/Template/ItemList.h"
#include <Manager/TriggerManager.h>
#include "../ProjectWindow.h"

using namespace CE;

namespace GUI::Widget
{
	class TriggerList : public Template::ItemList
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

			ListView(TriggerList* triggerList, TriggerManager* triggerManager)
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

			Item* createItem(Trigger::ITrigger* trigger) {
				auto eventHandler = new Events::EventHook(m_triggerList->m_eventClickOnName, trigger);
				return new TriggerItem(trigger, eventHandler);
			}
		protected:
			TriggerManager* m_triggerManager;
			TriggerList* m_triggerList;
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

		bool checkOnInputValue(Trigger::ITrigger* trigger, const std::string& value) {
			return Generic::String::ToLower(trigger->getName())
				.find(Generic::String::ToLower(value)) != std::string::npos;
		}

		bool checkAllFilters(Trigger::ITrigger* type) {
			return getFilterManager()->check([&type](Template::FilterManager::Filter* filter) {
				return static_cast<TriggerFilter*>(filter)->checkFilter(type);
			});
		}
		
		void setEventHandlerClickOnName(Events::Event* eventHandler) {
			m_eventClickOnName = eventHandler;
		}
	private:
		Events::Event* m_eventClickOnName = nullptr;
	};
};

namespace GUI::Window
{
	class TriggerList : public IWindow
	{
	public:
		TriggerList(Widget::TriggerList* triggerList = new Widget::TriggerList)
			: IWindow("Data type list")
		{
			setMainContainer(triggerList);
		}

		~TriggerList() {
			delete m_openFunctionCP;
		}

		Widget::TriggerList* getList() {
			return static_cast<Widget::TriggerList*>(getMainContainerPtr());
		}
	private:
		Events::EventHandler* m_openFunctionCP;
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