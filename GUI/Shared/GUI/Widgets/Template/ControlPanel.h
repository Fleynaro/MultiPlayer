#pragma once
#include "../../Items/IWidget.h"

namespace GUI::Widget::Template
{
	class ControlPanel
		: public Container
	{
	public:
		class SideBar
			: public ChildContainer
		{
		public:
			class MenuItem : public Elements::Button::ButtonStd
			{
			public:
				Container* m_container;

				MenuItem(const std::string& name, Container* container, Events::SpecialEventType::EventHandlerType* event)
					: Elements::Button::ButtonStd(name, event), m_container(container)
				{
					m_container->setParent(this);
				}

				~MenuItem() {
					m_container->destroy();
				}
			};

			SideBar()
				: ChildContainer()
			{
				m_menuEvent = Events::Listener(
					std::function([&](Events::ISender* sender_) {
						auto sender = static_cast<MenuItem*>(sender_);
						m_controlPanel->onSelectedContainer(sender->m_container);
						m_selectedContainer = sender->m_container;
					})
				);
				m_menuEvent->setCanBeRemoved(false);

				beginContainer(&m_menu);
			}

			~SideBar() {
				delete m_menuEvent;
			}

			void onVisibleOn() override {
				setWidth(static_cast<float>(getWidth()));
			}

			void addMenuItem(const std::string& name, Container* container)
			{
				getMenu()
					.addItem(
						(new MenuItem(
							name,
							container,
							m_menuEvent
						))
						->setWidth(static_cast<float>(getWidth()))
						->setHeight(static_cast<float>(getMenuItemHeight()))
					);
			}

			virtual int getWidth() {
				return 200;
			}

			virtual int getMenuItemHeight() {
				return 30;
			}

			Container& getMenu() {
				return *m_menu;
			}

			void setControlPanel(ControlPanel* controlPanel) {
				m_controlPanel = controlPanel;
			}

			void setSelectedContainer(Container* container) {
				m_selectedContainer = container;
			}

			Container* getSelectedContainer() {
				return m_selectedContainer;
			}
		protected:
			ControlPanel* m_controlPanel;
			Container* m_menu;
			Container* m_selectedContainer = nullptr;
		private:
			Events::SpecialEventType::EventHandlerType* m_menuEvent = nullptr;
		};

		ControlPanel()
		{
			m_sideBar = new SideBar;
			m_sideBar->setControlPanel(this);

			(*this)
				.addItem(m_sideBar)
				.sameLine()
				.beginChild()
					//.setVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 10))
					//.setVar(ImGuiStyleVar_ItemSpacing, ImVec2(10, 10))
					.beginImGui([&]() {
						m_sideBar->getSelectedContainer()->show();
					})
				.end();
		}

		virtual void onSelectedContainer(Container* container) {}

		SideBar* getSideBar() {
			return m_sideBar;
		}
	protected:
		SideBar* m_sideBar;
	};
};