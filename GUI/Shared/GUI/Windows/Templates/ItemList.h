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

		class Item : public TreeNode
		{
		public:
			Item(const std::string& header)
				: TreeNode(header)
			{}

			Item()
				: TreeNode("undefined")
			{}

			void setHeader(const std::string& header) {
				setName(header);
			}

			Container& beginBody()
			{
				return beginContainer();
			}
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
		
		void addFilter(Filter* filter) {
			m_filtersContainer->addItem(filter);
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
	};
};