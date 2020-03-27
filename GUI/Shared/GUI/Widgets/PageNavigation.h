#pragma once
#pragma once

#include "../Items/IWidget.h"


namespace GUI::Widget
{
	class PageNavigation : public Container
	{
	public:
		PageNavigation(int itemCount = 0, int itemCountOnPage = 0)
			: m_itemCount(itemCount), m_itemCountOnPage(itemCountOnPage), m_selectPageEvent(this, this)
		{
			m_goToPrev = Events::Listener(
				std::function([&](Events::ISender* sender) {
					if (getCurrentPage() - 1 <= 0)
						return;
					goToPrevPage();
					})
			);
			m_goToPrev->setCanBeRemoved(false);

			m_goToNext = Events::Listener(
				std::function([&](Events::ISender* sender) {
					if (getCurrentPage() + 1 > getLastPage())
						return;
					goToNextPage();
					})
			);
			m_goToNext->setCanBeRemoved(false);

			m_goTo = Events::Listener(
				std::function([&](Events::ISender* sender_) {
					auto sender = static_cast<GUI::Elements::Button::ButtonStd*>(sender_);
					auto page = std::stoi(sender->getName());
					goToPage(page);
					})
			);
			m_goTo->setCanBeRemoved(false);
		}

		~PageNavigation() {
			delete m_goToPrev;
			delete m_goToNext;
			delete m_goTo;
		}

		void update() {
			clear();
			generate();
		}

		auto& getSelectPageEvent() {
			return m_selectPageEvent;
		}
	private:
		Events::SpecialEventType::EventHandlerType* m_goToPrev = nullptr;
		Events::SpecialEventType::EventHandlerType* m_goToNext = nullptr;
		Events::SpecialEventType::EventHandlerType* m_goTo = nullptr;
		Events::Event<int, int> m_selectPageEvent;

		class PageBtn : public Elements::Button::ButtonStd
		{
		public:
			int m_idx;
			bool m_selected = false;

			PageBtn(const std::string& name, Events::SpecialEventType::EventHandlerType* eventHandler, int idx)
				: Elements::Button::ButtonStd(name, eventHandler), m_idx(idx)
			{}

			void select() {
				m_selected = true;
			}

			void render() override
			{
				Elements::Button::ButtonStd::render();
				if (m_selected) {
					drawBorder(0xFF0000FF);
				}
			}
		};


		void generate()
		{
			if (getLastPage() == 1)
				return;

			int page = getCurrentPage() - getPageCountOnSide();

			newLine();
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

		PageBtn* addNextButton(const std::string& name, Events::SpecialEventType::EventHandlerType* eventHandler, int idx = -1)
		{
			PageBtn* btn;
			sameLine().addItem(
				btn = new PageBtn(
					name,
					eventHandler,
					idx
				)
			);
			return btn;
		}

		void addNextNumButton(int page)
		{
			auto btn = addNextButton(std::to_string(page), m_goTo, page);
			if (page == getCurrentPage()) {
				btn->select();
			}
		}

		void addNextThreeDots()
		{
			(*this)
				.sameLine()
				.text("...");
		}

		void setCurrentPage(int page) {
			m_currentPage = page;
		}

		int getPageCountOnSide() {
			return m_buttonCount / 2;
		}
	public:
		int getItemCount() {
			return m_itemCount;
		}

		void setItemCount(int amount) {
			m_itemCount = amount;
		}

		int getItemCountOnPage() {
			return m_itemCountOnPage;
		}

		void setItemCountOnPage(int amount) {
			m_itemCountOnPage = amount;
		}

		int getCurrentPage() {
			return m_currentPage;
		}

		int getLastPage() {
			return (getItemCount() - 1) / getItemCountOnPage() + 1;
		}

		bool isPageValid(int page) {
			return page >= 1 && page <= getLastPage();
		}

		void goToPage(int page)
		{
			m_selectPageEvent.invoke(getCurrentPage(), page);
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
		int m_itemCount;
		int m_itemCountOnPage;
		int m_currentPage = 1;
		int m_buttonCount = 3;
	};
};