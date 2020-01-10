#pragma once

#include "SDK/World/Vehicle/Vehicle.h"
#include "IGamePoolManager.h"

namespace GUI::Widget
{
	class GameVehiclePoolManager
		: public IGamePoolManager
	{
	public:
		GameVehiclePoolManager()
		{}

		void updateList() override {
			clearCats();
			getMainContainer().clear();

			addNextPageNav();

			SDK::Pool::Vehicle iterator;
			while (iterator.hasNext())
			{
				auto veh = SDK::Vehicle(iterator.next());
				auto& category = beginCategory(std::to_string(veh.getId()));
				buildCategory(category, veh);
			}

			addNextPageNav();
			showAll();
		}

		void buildCategory(Category& cat, SDK::Vehicle& veh)
		{
			auto item = new Item;
			cat.addItem(item);

			auto addr = String::NumberToHex(veh.getAddr());
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

			item->setKeywordList({ std::to_string(veh.getId()), String::ToLower(addr) });
		}
	};
};