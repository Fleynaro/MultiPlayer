#pragma once

#include "../../Widgets/GamePoolManager/GamePedPoolManager.h"
#include "../../Widgets/GamePoolManager/GameVehiclePoolManager.h"
#include "../Templates/ManagerWin.h"

namespace GUI::Window
{
	class GamePoolManager : public Template::ManagerStd
	{
	public:
		enum class Pool {
			Ped,
			Vehicle
		};

		GamePoolManager()
			: Template::ManagerStd("Game pool manager")
		{
			Template::ManagerStd::makeMainContainer(
				getMainContainer(),
				bodyLeft(),
				bodyRight()
			);

			initPools();
			selectPool(Pool::Ped);
		}

		void initPools()
		{
			m_pedPool = new Widget::GamePedPoolManager;
			m_vehPool = new Widget::GameVehiclePoolManager;
		}

		void onRender() override
		{
			m_selectedPool->updateList();
		}

		void selectPool(Pool pool)
		{
			m_body->clear();

			switch (pool)
			{
			case Pool::Ped:
				m_selectedPool = m_pedPool;
				break;
			case Pool::Vehicle:
				m_selectedPool = m_vehPool;
				break;
			}

			m_body->addItem(m_selectedPool->getMainContainerPtr());
		}

		Elements::List::ListBox* m_poolsList = nullptr;
		Container* bodyLeft()
		{
			Container* container = new Container;
			(*container)
				.text("Select a pool")
				.addItem
				(
					(new Elements::List::ListBox("", 0,
						new Events::EventUI(EVENT_LAMBDA(info)
						{
							auto sender = (Elements::List::ListBox*)info->getSender();
							selectPool((Pool)sender->getSelectedItem());
						})
					))
					->addItem("Peds")
					->addItem("Vehicles")
					->addItem("Objects")
					->setWidth(m_divLeft - 15)
					->setHeight(-1),
					(Item **)&m_poolsList
				);
			return container;
		}

		Container* m_body = nullptr;
		Container* bodyRight()
		{
			return m_body = new Container;
		}
	private:
		Widget::IGamePoolManager* m_selectedPool = nullptr;
		Widget::GamePedPoolManager* m_pedPool = nullptr;
		Widget::GameVehiclePoolManager* m_vehPool = nullptr;
	};
};