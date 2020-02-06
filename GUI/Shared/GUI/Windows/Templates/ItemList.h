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

	protected:
		class Filter : public ColContainer
		{
		public:
			Filter(const std::string& name)
				: ColContainer(name)
			{}

			void buildHeader(const std::string description = "")
			{
				(*this)
					.setCloseBtn(false)
					.text(description)
					.separator();
			}

			Container& beginBody()
			{
				return beginContainer();
			}

			virtual bool isDefined() = 0;
		};
		
		class FilterConditionList
		{
		public:
			enum Operation {
				And,
				AndNot,
				Or,
				OrNot
			};

			void addFilter(Operation operation, Filter* filter) {
				m_filters.push_back(filter);
				m_conditions.insert(std::make_pair(filter, operation));

			}

			void remove(Filter* filter) {
				m_filters.remove(filter);
				m_conditions.erase(filter);
			}
			
			bool check(std::function<bool(Filter*)> callback) {
				bool result = 1;
				for (auto filter : m_filters) {
					switch (m_conditions[filter])
					{
					case And:
					case AndNot:
						result &= callback(filter) ^ (m_conditions[filter] == AndNot);
						break;
					case Or:
					case OrNot:
						if (result |= callback(filter) ^ (m_conditions[filter] == OrNot))
							return true;
						break;
					}
				}
				return result;
			}
		private:
			std::list<Filter*> m_filters;
			std::map<Filter*, Operation> m_conditions;
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

	private:
		Container* m_filtersContainer = nullptr;
		Container* m_itemsContainer = nullptr;

		std::string m_oldInputValue = "";

	protected:
		ItemList(const std::string& name, const StyleSettings& style)
			: IWindow(name)
		{
			setWidth(style.m_width);
			setHeight(style.m_height);

			getMainContainer()
				.beginChild("#left")
					.setWidth(style.m_leftWidth)
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
								->setWidth(style.m_leftWidth)
							)
						.end()
						.newLine()
					.end()
				
					.text("You may use filters")
					.beginContainer((Container**)& m_filtersContainer)
						//list of filters
					.end()
				.end()
				.sameLine()
				.beginChild("##body", (ChildContainer**)& m_itemsContainer)
					//list of items
				.end();
		}
		
		FilterConditionList& getFilters() {
			return m_filters;
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

		private:
			FilterConditionList m_filters;
	};
};