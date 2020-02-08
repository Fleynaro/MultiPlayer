#pragma once

#include "../../Items/IWindow.h"

namespace GUI::Window::Template
{
	class ItemList : public IWindow
	{
	public:
		struct StyleSettings
		{
			int m_width = 700;
			int m_height = 500;
			int m_leftWidth = 200;
		};

		inline static StyleSettings DefaultStyleSettings;
	protected:
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
				: public ColContainer,
				public Events::ISender
			{
			public:
				Filter(const std::string& name, Operation condition = And)
					: m_condition(condition), ColContainer(name)
				{}

				void buildHeader(const std::string description = "")
				{
					m_eventChangeCondition = new Events::EventUI(EVENT_LAMBDA(info) {
						auto sender = static_cast<FilterConditionSelector*>(info->getSender());
						m_condition = sender->getSelectedOperation();
					});

					(*this)
						.setCloseBtn(false)
						.addItem(new FilterConditionSelector(m_eventChangeCondition, getCondition()))
						.sameLine().addItem(
							new GUI::Elements::Button::ButtonStd(
								"x",
								m_eventRemoveHook = new Events::EventHook(this)
							)
						)
						.text(description)
						.separator();
				}

				Container& beginBody()
				{
					return beginContainer();
				}

				virtual bool isDefined() = 0;

				Operation getCondition() {
					return m_condition;
				}

				void setEventRemoveHandler(Events::Event* eventHandler) {
					m_eventRemoveHook->setEventHandler(eventHandler);
				}
			private:
				Operation m_condition;
				Events::Event* m_eventChangeCondition;
				Events::EventHook* m_eventRemoveHook;
			};

			class FilterCreator
				: public Elements::List::Combo
			{
			public:
				FilterCreator(FilterManager* filterManager)
					: m_filterManager(filterManager), Elements::List::Combo("")
				{
					addItem("<Add a filter>");
					setSpecialEvent(new Events::EventUI(EVENT_LAMBDA(info) {
						int filterIdx = getSelectedItem() - 1;
						if (filterIdx != -1) {
							m_filterManager->addFilter(createFilter(filterIdx));
							setDefault(0);
						}
					}));
				}

				virtual Filter* createFilter(int idx) = 0;
			private:
				FilterManager* m_filterManager;
			};

			FilterManager() {
				m_eventRemoveFilter = new Events::EventUI(EVENT_LAMBDA(info) {
					auto sender = static_cast<Events::EventHook*>(info->getSender());
					auto filter = static_cast<Filter*>(sender->getUserDataPtr());
					remove(filter);
					delete filter;
				});
				m_eventRemoveFilter->setCanBeRemoved(false);
			}

			~FilterManager() {
				delete m_eventRemoveFilter;
			}

			void addFilter(Filter* filter) {
				m_filters.push_back(filter);
				filter->setEventRemoveHandler(m_eventRemoveFilter);
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
		private:
			std::list<Filter*> m_filters;
			Events::Event* m_eventRemoveFilter;
		};

		class Item : public TreeNode
		{
		public:
			Item(const std::string& header)
				: TreeNode(header)
			{}

			Item()
				: TreeNode()
			{}

			~Item() {
				if (m_header != nullptr && m_header->canBeRemovedBy(this)) {
					delete m_header;
				}
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

		private:
			Container* m_header = nullptr;
		};

	public:
		Container* m_underFilterCP = nullptr;
	private:
		Container* m_filtersContainer = nullptr;
		Container* m_itemsContainer = nullptr;

		std::string m_oldInputValue = "";

	protected:
		ItemList(const std::string& name, FilterManager::FilterCreator* filterCreator, StyleSettings* styleSettings = &DefaultStyleSettings)
			: IWindow(name), m_styleSettings(styleSettings)
		{
			setWidth(m_styleSettings->m_width);
			setHeight(m_styleSettings->m_height);
			filterCreator->setWidth(m_styleSettings->m_leftWidth);

			getMainContainer()
				.beginChild()
					.setWidth(m_styleSettings->m_leftWidth)
					.beginContainer()
						.text("Search")
						.separator()
						.beginContainer()
							.addItem(
								(new GUI::Elements::Input::Text(
									"##input1", 50,
									new Events::EventUI(EVENT_LAMBDA(info) {
										auto sender = (GUI::Elements::Input::Text*)info->getSender();
										onSearch(sender->getInputValue());
										m_oldInputValue = sender->getInputValue();
									})
								))
								->setWidth(m_styleSettings->m_leftWidth)
							)
						.end()
						.newLine()
					.end()
				
					.text("You may use filters")
					.addItem(getFilterManager())
					.newLine()
					.separator()
					.addItem(filterCreator)
					.addItem(m_underFilterCP = new Container)
				.end()
				.sameLine()
				.beginChild((ChildContainer**)& m_itemsContainer)
					//list of items
				.end();
		}
		
		FilterManager* getFilterManager() {
			return &m_filterManager;
		}

		void add(Item* item) {
			m_itemsContainer->addItem(item);
		}

		void clear() {
			m_itemsContainer->clear();
		}

		virtual void onSearch(const std::string& value) = 0;

		virtual void update() {
			onSearch(getOldInputValue());
		}

		const std::string& getOldInputValue() {
			return m_oldInputValue;
		}

		StyleSettings* m_styleSettings;
	private:
		FilterManager m_filterManager;
	};
};