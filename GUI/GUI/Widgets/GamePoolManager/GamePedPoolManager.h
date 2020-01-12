#pragma once

#include "SDK/World/Ped/Ped.h"
#include "IGamePoolManager.h"

namespace GUI::Widget
{
	class GamePedPoolManager
		: public IGamePoolManager
	{
	public:
		GamePedPoolManager()
		{}

		void updateList() override {
			clearCats();
			getMainContainer().clear();

			addNextPageNav();

			SDK::Pool::Ped iterator;
			while (iterator.hasNext())
			{
				auto ped = SDK::Ped(iterator.next());
				auto& category = beginCategory(std::to_string(ped.getId()));
				buildCategory(category, ped);
			}

			addNextPageNav();
			showAll();
		}

		void buildCategory(Category& cat, SDK::Ped& ped)
		{
			auto item = new Item;
			cat.addItem(item);

			auto addr = String::NumberToHex(ped.getAddr());
			(*item->getContainer())
				.separator()
				.text("Address: ").sameLine(0.f)
				.addItem(
					new TypeView::TextToCopy(
						"0x" + addr,
						ColorRGBA(0xC5F5D5AA),
						m_clickTextToCopy
					)
				);

			item->setKeywordList({ std::to_string(ped.getId()), String::ToLower(addr) });
		}
	};
};