#pragma once
#include "../../Items/IWidget.h"

namespace GUI::Widget::Template
{
	class FilterManager : public Item
	{
	public:
		enum Operation {
			And,
			AndNot,
			Or,
			OrNot
		};

		class FilterConditionSelector : public Elements::List::Combo
		{
		public:
			FilterConditionSelector(Events::Event* event, Operation condition)
				: Elements::List::Combo(getUniqueId(), condition, event)
			{
				addItem("And");
				addItem("And not");
				addItem("Or");
				addItem("Or not");
			}

			Operation getSelectedOperation() {
				return (Operation)getSelectedItem();
			}
		};

		class Filter
			: public ColContainer
		{
		public:
			Filter(FilterManager* filterManager, const std::string& name, Operation condition = And)
				: m_filterManager(filterManager), m_condition(condition), m_removeFilterEvent(this), ColContainer(name)
			{}

			void buildHeader(const std::string description = "", bool isFixed = false)
			{
				m_eventChangeCondition = new Events::EventUI(EVENT_LAMBDA(info) {
					auto sender = static_cast<FilterConditionSelector*>(info->getSender());
					m_condition = sender->getSelectedOperation();
					onChanged();
				});

				(*this)
					.setCloseBtn(false);
				if (!isFixed) {
					(*this)
						.addItem(new FilterConditionSelector(m_eventChangeCondition, getCondition()))
						.sameLine().addItem(
							new GUI::Elements::Button::ButtonStd(
								"x",
								new Events::EventUI(EVENT_LAMBDA(info) {
									getRemoveFilterEvent().invoke();
								})
							)
						);
				}
				else {
					setOpen(true);
				}
				(*this)
					.text(description)
					.separator();
			}

			void onChanged() {
				m_filterManager->getUpdateEvent().invoke();
			}

			Container& beginBody()
			{
				return beginContainer();
			}

			virtual bool isDefined() = 0;

			Operation getCondition() {
				return m_condition;
			}

			Events::Messager& getRemoveFilterEvent() {
				return m_removeFilterEvent;
			}
		private:
			Operation m_condition;
			Events::Event* m_eventChangeCondition;
			Events::Messager m_removeFilterEvent;
			FilterManager* m_filterManager;
		};
		friend class Filter;


		class FilterCreator
			: public Elements::List::Combo
		{
		public:
			FilterCreator(FilterManager* filterManager)
				: m_filterManager(filterManager), Elements::List::Combo("")
			{
				addItem("<Add a filter>");
				getSpecialEvent() += new Events::EventUI(EVENT_LAMBDA(info) {
					int filterIdx = getSelectedItem() - 1;
					if (filterIdx != -1) {
						m_filterManager->addFilter(createFilter(filterIdx));
						setDefault(0);
						m_filterManager->getUpdateEvent().invoke();
					}
				});
			}

			virtual Filter* createFilter(int idx) = 0;
		private:
			FilterManager* m_filterManager;
		};
		friend class FilterCreator;

		FilterManager()
			: m_updateEvent(this)
		{
			m_eventRemoveFilter = new Events::EventUI(EVENT_LAMBDA(info) {
				auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
				auto filter = static_cast<Filter*>(message->getUserDataPtr());
				remove(filter);
				delete filter;
				getUpdateEvent().invoke();
			});
			m_eventRemoveFilter->setCanBeRemoved(false);
		}

		~FilterManager() {
			delete m_eventRemoveFilter;
		}

		void addFilter(Filter* filter) {
			filter->setParent(this);
			m_filters.push_back(filter);
			filter->getRemoveFilterEvent() += m_eventRemoveFilter;
		}

		void remove(Filter* filter) {
			m_filters.remove(filter);
		}

		bool check(std::function<bool(Filter*)> callback) {
			bool result = 1;
			for (auto filter : m_filters) {
				bool filterResult = !filter->isDefined() || callback(filter);

				switch (filter->getCondition())
				{
				case And:
				case AndNot:
					result &= filterResult ^ (filter->getCondition() == AndNot);
					break;
				case Or:
				case OrNot:
					if (result |= filterResult ^ (filter->getCondition() == OrNot))
						return true;
					break;
				}
			}
			return result;
		}

		void render() override {
			for (auto filter : m_filters) {
				filter->render();
			}
		}

		std::list<Filter*>& getFilters() {
			return m_filters;
		}

		Events::Messager& getUpdateEvent() {
			return m_updateEvent;
		}
	private:
		std::list<Filter*> m_filters;
		Events::Event* m_eventRemoveFilter;
		Events::Messager m_updateEvent;
	};

	class ItemList : public Container
	{
	public:
		struct StyleSettings
		{
			int m_height;
			int m_rightWidth;
			int m_leftWidth;

			StyleSettings()
			{
				m_height = 500;
				m_rightWidth = 500;
				m_leftWidth = 200;
			}
		};

		class IView
		{
		public:
			virtual void onSetView() {}
			virtual void onSearch(const std::string& value) = 0;
			
			void setOutputContainer(Container* container) {
				m_outContainer = container;
			}

			Container* getOutContainer() {
				return m_outContainer;
			}
		private:
			Container* m_outContainer = nullptr;
		};
	protected:
		

		class Item : public TreeNode
		{
		public:
			Item(const std::string& header)
				: TreeNode(header)
			{
				addFlags(ImGuiTreeNodeFlags_FramePadding);
			}

			Item()
				: TreeNode()
			{
				addFlags(ImGuiTreeNodeFlags_FramePadding);
			}

			~Item() {
				if(m_header != nullptr)
					m_header->destroy();
			}

			void setHeader(const std::string& header) {
				setName(header);
			}

			Container& beginHeader()
			{
				m_header = new Container;
				m_header->setParent(this);
				return *m_header;
			}

			Container& beginBody()
			{
				return (*this);
			}

			void renderHeader() override {
				m_header->render();
			}

			Container* m_header = nullptr;
		};
	public:
		virtual void setView(IView* view, bool isUpdate = true) {
			m_view = view;
			m_view->setOutputContainer(m_itemsContainer);
			m_view->onSetView();
			if (isUpdate) {
				update();
			}
		}

		virtual void update() {
			onSearch(getOldInputValue());
		}

		void doSearchRequest(const std::string& text) {
			onSearch(text);
			m_oldInputValue = text;
		}
	private:
		Container* m_filtersContainer = nullptr;
		ChildContainer* m_itemsContainer = nullptr;

		std::string m_oldInputValue = "";

	protected:
		ItemList(FilterManager::FilterCreator* filterCreator, FilterManager* filterManager = new FilterManager, StyleSettings styleSettings = StyleSettings())
			: m_filterCreator(filterCreator), m_filterManager(filterManager), m_styleSettings(styleSettings)
		{
			m_filterManager->setParent(this);
			m_filterManager->getUpdateEvent() += new Events::EventUI(EVENT_LAMBDA(info) {
				update();
			});
			m_filterCreator->setWidth(m_styleSettings.m_leftWidth);

			(*this)
				.beginChild()
					.setWidth(m_styleSettings.m_leftWidth)
					.beginContainer()
						.text("Search")
						.separator()
						.beginContainer()
							.addItem(
								(new GUI::Elements::Input::Text(
									"##input1",
									new Events::EventUI(EVENT_LAMBDA(info) {
										auto sender = (GUI::Elements::Input::Text*)info->getSender();
										doSearchRequest(sender->getInputValue());
									})
								))
								->setWidth(m_styleSettings.m_leftWidth)
							)
						.end()
						.newLine()
					.end()
				
					.text("You may use filters")
					.addItem(getFilterManager())
					.newLine()
					.separator()
					.addItem(m_filterCreator)
					.addItem(m_underFilterCP = new Container)
				.end()
				.sameLine()
				.beginChild((ChildContainer**)& m_itemsContainer)
					//list of items
				.end();
		}

		ChildContainer& getItemsContainer() {
			return *m_itemsContainer;
		}

		void onSearch(const std::string& value) {
			m_view->onSearch(value);
		}

		const std::string& getOldInputValue() {
			return m_oldInputValue;
		}
	public:
		FilterManager* getFilterManager() {
			return m_filterManager;
		}

		StyleSettings m_styleSettings;
		FilterManager::FilterCreator* m_filterCreator;
		Container* m_underFilterCP = nullptr;
	private:
		FilterManager* m_filterManager;
	protected:
		IView* m_view = nullptr;
	};


	template<typename T>
	class SelectableItemList : public ItemList
	{
	public:
		class SelectedFilter : public FilterManager::Filter
		{
		public:
			SelectedFilter(SelectableItemList* selectableItemList)
				: m_selectableItemList(selectableItemList), Filter(selectableItemList->getFilterManager(), "Selected items filter")
			{
				buildHeader("Filter items by selected.", true);
				beginBody()
					.addItem(
						m_cb = new Elements::Generic::Checkbox("show selected only", false,
							new Events::EventUI(EVENT_LAMBDA(info) {
								onChanged();
							})
						)
					);
			}

			bool checkFilter(T* item) {
				return m_selectableItemList->isItemSelected(item);
			}

			bool isDefined() override {
				return m_cb->isSelected();
			}
		private:
			Elements::Generic::Checkbox* m_cb;
			SelectableItemList* m_selectableItemList;
		};

		class SelectableItem : public GUI::Item
		{
		public:
			SelectableItem(ItemList::Item* item, bool selected, Events::Event* eventSelect = nullptr)
				: m_item(item)
			{
				m_item->setParent(this);
				(*m_item->m_header)
					.beginReverseInserting()
						.sameLine()
						.addItem(m_cb = new Elements::Generic::Checkbox("", selected, eventSelect))
						.sameLine()
					.endReverseInserting();
			}

			~SelectableItem() {
				m_item->destroy();
			}

			void render() override {
				m_item->render();
			}

			Events::Messager& getSelectedEvent() {
				return m_cb->getSpecialEvent();
			}
		private:
			ItemList::Item* m_item;
			Elements::Generic::Checkbox* m_cb;
		};

		SelectedFilter* m_selectedFilter;

		SelectableItemList(ItemList* itemList, Events::Event* eventSelectItems)
			: m_itemList(itemList), ItemList(itemList->m_filterCreator, itemList->getFilterManager(), itemList->m_styleSettings)
		{
			getFilterManager()->addFilter(m_selectedFilter = new SelectedFilter(this));
			m_itemList->setParent(this);

			m_eventSelectItem = new Events::EventUI(EVENT_LAMBDA(info) {
				auto message = std::dynamic_pointer_cast<Events::EventHookedMessage>(info);
				auto chekbox = static_cast<Elements::Generic::Checkbox*>(message->getSender());
				auto item = (T*)message->getUserDataPtr();
				if (chekbox->isSelected()) {
					m_selectedItems.push_back(item);
				}
				else {
					m_selectedItems.remove(item);
				}
			});
			m_eventSelectItem->setCanBeRemoved(false);

			class UpdSelectInfo : public Container
			{
			public:
				UpdSelectInfo(SelectableItemList* selectableItemList, Events::Event* event)
					: m_selectableItemList(selectableItemList)
				{
					newLine();
					newLine();
					separator();
					addItem(m_button = new Elements::Button::ButtonStd("Select", event));
				}

				void render() override {
					Container::render();
					m_button->setName("Select " + std::to_string(m_selectableItemList->getSelectedItemsCount()) + " items");
				}

				bool isShown() override {
					return m_selectableItemList->getSelectedItemsCount() > 0;
				}
			private:
				SelectableItemList* m_selectableItemList;
				Elements::Button::ButtonStd* m_button;
			};

			if (eventSelectItems != nullptr) {
				(*m_itemList->m_underFilterCP)
					.addItem(new UpdSelectInfo(this, eventSelectItems));
			}
		}

		~SelectableItemList() {
			m_itemList->destroy();
		}

		void setView(IView* view, bool isUpdate = true) override {
			m_view = view;
			m_itemList->setView(view, isUpdate);
		}

		void render() override {
			m_itemList->render();
		}

		bool isItemSelected(T* item) {
			for (auto it : getSelectedItems()) {
				if (it == item)
					return true;
			}
			return false;
		}

		int getSelectedItemsCount() {
			return getSelectedItems().size();
		}

		std::list<T*>& getSelectedItems() {
			return m_selectedItems;
		}

		Events::Event* m_eventSelectItem;
	protected:
		ItemList* m_itemList;
		std::list<T*> m_selectedItems;
	};




	class ItemInput
		: public Elements::Input::Text,
		public Attribute::Collapse<ItemInput>
	{
	public:
		ItemInput(const std::string& name = "")
			: Elements::Input::Text(name, nullptr), Attribute::Collapse<ItemInput>(false)
		{
			m_placeHolderEnable = true;
		}

		bool m_focused = true;
		void render() override {
			Text::render();
			ImGui::SameLine();

			if (ImGui::IsItemHovered()) {
				if(!toolTip().empty())
					ImGui::SetTooltip(toolTip().c_str());
			}

			m_open |= ImGui::IsItemActive();
			m_open &= m_focused;

			if (isOpen())
			{
				ImGui::SetNextWindowPos({ ImGui::GetItemRectMin().x, ImGui::GetItemRectMax().y });
				ImGui::SetNextWindowSize({ 0, 0 });

				bool open = m_open;
				if (ImGui::Begin(getUniqueId().c_str(), &open, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_ChildWindow2))
				{
					m_focused &= ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows);
					renderShortView();
					ImGui::End();
				}
			}
			else {
				m_focused = true;
			}
		}

		void onSpecial() override {
			Elements::Input::Text::onSpecial();
			onSearch(getInputValue());
		}

		void refresh() {
			onSpecial();
		}

		virtual std::string toolTip() = 0;
		virtual void renderShortView() = 0;
		virtual void onSearch(const std::string& text) = 0;
	};
};