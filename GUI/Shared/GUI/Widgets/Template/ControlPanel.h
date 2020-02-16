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

				MenuItem(const std::string& name, Container* container, Events::Event* event)
					: Elements::Button::ButtonStd(name, event), m_container(container)
				{}
			};

			SideBar()
				: ChildContainer()
			{
				m_menuEvent = new Events::EventUI(EVENT_LAMBDA(info) {
					auto sender = static_cast<MenuItem*>(info->getSender());
					m_controlPanel->onSelectedContainer(sender->m_container);
					m_selectedContainer = sender->m_container;
				});
			}

			~SideBar() {
				delete m_menuEvent;
			}

			void onVisibleOff() override {
				clear();
			}

			void onVisibleOn() override {
				(*this)
					.setWidth(getWidth())
					.beginContainer(&m_menu);
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
						->setWidth(getWidth())
						->setHeight(getMenuItemHeight())
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
			Events::EventUI* m_menuEvent = nullptr;
		};

		ControlPanel()
		{
			m_sideBar = new SideBar;
			getSideBar()->setControlPanel(this);

			(*this)
				.addItem(getSideBar())
				.sameLine()
				.beginChild()
					//.setVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 10))
					//.setVar(ImGuiStyleVar_ItemSpacing, ImVec2(10, 10))
					.beginImGui([&]() {
						getSideBar()->getSelectedContainer()->show();
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