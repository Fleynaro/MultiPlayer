#pragma once
#pragma once

#include "../Items/IWidget.h"

namespace GUI::Widget
{
	class PageNavigation : public IWidget
	{
	public:
		PageNavigation(uint32_t itemCount = 0, uint32_t itemCountOnPage = 0)
			: IWidget("page nav"), m_itemCount(itemCount), m_itemCountOnPage(itemCountOnPage)
		{
			setDefaultHandlers();
		}

		~PageNavigation() {
			delete m_goToPrev;
			delete m_goToNext;
			delete m_goTo;
			delete m_pageSelected;
		}

		void setDefaultHandlers()
		{
			m_goToPrev = new Events::EventUI(
				EVENT_LAMBDA(info) {
					if (getCurrentPage() - 1 <= 0)
						return;
					goToPrevPage();
					sendPageSelectedEventMessage(info);
				}
			);
			m_goToPrev->setCanBeRemoved(false);

			m_goToNext = new Events::EventUI(
				EVENT_LAMBDA(info) {
					if (getCurrentPage() + 1 > getLastPage())
						return;
					goToNextPage();
					sendPageSelectedEventMessage(info);
				}
			);
			m_goToNext->setCanBeRemoved(false);

			m_goTo = new Events::EventUI(
				EVENT_LAMBDA(info) {
					auto sender = (GUI::Elements::Button::ButtonStd*)info->getSender();
					auto page = std::stoi(sender->getName());
					goToPage(page);
					sendPageSelectedEventMessage(info);
				}
			);
			m_goTo->setCanBeRemoved(false);
		}

		void update() {
			getMainContainer().clear();
			generate();
		}

		void setEventListener(Events::Event* pageSelected)
		{
			m_pageSelected = pageSelected;
		}
	private:
		Events::Event* m_goToPrev = nullptr;
		Events::Event* m_goToNext = nullptr;
		Events::Event* m_goTo = nullptr;

		Events::Event* m_pageSelected = nullptr;
		void sendPageSelectedEventMessage(Events::EventInfo::Type& info)
		{
			m_pageSelected->callHandler(info);
		}

		void generate()
		{
			if (getLastPage() == 1)
				return;

			auto page = getCurrentPage() - getPageCountOnSide();

			addNextButton("<", m_goToPrev);
			addNextNumButton(1);
			
			if(page > 2)
				addNextThreeDots();

			while (page <= getCurrentPage() + getPageCountOnSide())
			{
				if (page > 1 && page < getLastPage())
				{
					addNextNumButton(page);
				}
				page++;
			}

			if (page < getLastPage() - 2)
				addNextThreeDots();
			addNextNumButton(getLastPage());
			addNextButton(">", m_goToNext);
		}

		GUI::Elements::Button::ButtonStd* addNextButton(std::string name, Events::Event* event)
		{
			GUI::Elements::Button::ButtonStd* btn = nullptr;
			getMainContainer()
				.sameLine().addItem(
					new GUI::Elements::Button::ButtonStd(
						name,
						event
					),
					(GUI::Item**)&btn
				);

			return btn;
		}

		void addNextNumButton(uint32_t page)
		{
			auto btn = addNextButton(std::to_string(page), m_goTo);
			if (page == getCurrentPage()) {
				btn->setFont(GUI::Font::Tahoma_H3);
			}
		}

		void addNextThreeDots()
		{
			getMainContainer()
				.sameLine().text("...");
		}

		void setCurrentPage(uint32_t page) {
			m_currentPage = page;
		}

		uint32_t getPageCountOnSide() {
			return m_buttonCount / 2;
		}
	public:
		uint32_t getItemCount() {
			return m_itemCount;
		}

		void setItemCount(uint32_t amount) {
			m_itemCount = amount;
		}

		uint32_t getItemCountOnPage() {
			return m_itemCountOnPage;
		}

		void setItemCountOnPage(uint32_t amount) {
			m_itemCountOnPage = amount;
		}

		uint32_t getCurrentPage() {
			return m_currentPage;
		}

		uint32_t getLastPage() {
			return getItemCount() / getItemCountOnPage() + 1;
		}

		bool isPageValid(uint32_t page) {
			return page >= 1 && page <= getLastPage();
		}

		void goToPage(uint32_t page)
		{
			setCurrentPage(page);
			update();
		}

		void goToNextPage() {
			goToPage(getCurrentPage() + 1);
		}

		void goToPrevPage() {
			goToPage(getCurrentPage() - 1);
		}
	private:
		uint32_t m_itemCount;
		uint32_t m_itemCountOnPage;
		uint32_t m_currentPage = 0;
		uint32_t m_buttonCount = 3;
	};
};