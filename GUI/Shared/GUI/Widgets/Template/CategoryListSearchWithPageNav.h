#pragma once

#include "CategoryListSearch.h"
#include "../PageNavigation.h"

namespace GUI::Widget::Template
{
	class CategoryListSearchWithPageNav : public CategoryListSearch
	{
	public:
		CategoryListSearchWithPageNav(Widget::PageNavigation* pageNav = new Widget::PageNavigation(0, 30))
			: m_pageNav(pageNav)
		{
			getPageNav()->setEventListener(new Events::EventStd(
				EVENT_LAMBDA(info) {
					goToPage(getPageNav()->getCurrentPage());
				}
			));
		}

		~CategoryListSearchWithPageNav() {
			delete m_pageNav;
		}

		void updateOnInputValue(std::string inputValue) override
		{
			CategoryListSearch::updateOnInputValue(inputValue);

			int itemCount = 0;
			int catCount = 0;
			for (auto category : getCatList()) {
				itemCount += category->m_relItemCount;
				if (category->m_relItemCount > 0) {
					catCount++;
				}
			}

			getPageNav()->setItemCount(catCount);

			m_pageCat.clear();
			m_pageCat.resize(getPageNav()->getLastPage());
			int idx = 0;
			for (auto category : getCatList()) {
				if (category->isHide())
					continue;
				addCategoryToCurrentPage(
					category,
					idx / getPageNav()->getItemCountOnPage()
				);
				idx++;
			}

			hideAllCategories();
			goToPage(1, false);
		}

		void addCategoryToCurrentPage(Category* cat, int page)
		{
			m_pageCat[page].push_back(cat);
		}

		int m_lastPage = 0;
		void goToPage(int page, bool hide = true)
		{
			if (hide)
			{
				for (auto const& cat : m_pageCat[m_lastPage - 1]) {
					hideCategory(cat);
				}
			}

			for (auto const& cat : m_pageCat[page - 1]) {
				showCategory(cat);
			}

			getPageNav()->goToPage(page);
			m_lastPage = page;
		}

		void addNextPageNav()
		{
			getMainContainer()
				.newLine()
				.addItem(getPageNav()->getMainContainerPtr());
		}

		Widget::PageNavigation* getPageNav() {
			return m_pageNav;
		}
	private:
		std::vector<std::list<Category*>> m_pageCat;
		Widget::PageNavigation* m_pageNav = nullptr;
	};
};