#pragma once

#include "GUI/Items/Items.h"
#include "GUI/Items/StyleThemes.h"
#include "GUI/Items/IWindow.h"
#include "GUI/Items/IWidget.h"
#include "TestWindows.h"

using namespace GUI::Window;
using namespace GUI::Widget;

class UI
{
public:
	UI() {
	
	}

	class ControlPanel : public IWidget
	{
	public:
		class SideBar : public ChildContainer, public IInit
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
				: ChildContainer("#sidebar")
			{}

			~SideBar() {
				delete m_menuEvent;
			}

			void init() override {
				(*this)
					.setWidth(getWidth())
					.beginContainer(&m_menu);

				m_menuEvent = new Events::EventUI(EVENT_LAMBDA(info) {
					auto sender = static_cast<MenuItem*>(info->getOwner());
					m_controlPanel->onSelectedContainer(sender->m_container);
					m_selectedContainer = sender->m_container;
				});
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
			: IWidget("control panel")
		{
			m_sideBar = new SideBar;
			m_sideBar->init();
			getSideBar()->setControlPanel(this);

			getMainContainer()
				.addItem(getSideBar())
				.sameLine()
				.beginChild("#right")
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


	class FunctionCP : public ControlPanel
	{
	public:
		Container* m_generic;
		Container* m_callFunction;

		FunctionCP()
			: ControlPanel()
		{
			getSideBar()->addMenuItem("Generic", m_generic = new Container);
			getSideBar()->addMenuItem("Call", m_callFunction = new Container);
			getSideBar()->setSelectedContainer(m_generic);

			buildGeneric();
			buildCallFunction();
		}

		void buildGeneric()
		{
			(*m_generic)
				.text("generic");
		}

		void buildCallFunction()
		{
			(*m_callFunction)
				.text("callFunction");
		}
	};

	class WindowTest : public IWindow
	{
	public:
		//bool m_selected
		
		WindowTest()
			: IWindow("ImGui window for test")
		{
			getMainContainer()
				.addItem((new FunctionCP)->getMainContainerPtr())
				.beginImGui([]() {
				

				});
		}
	};

	class WinManager
	{
	public:
		static void registerWindows() {
			UI::WinManager::addWindow(new WindowTest);
		}

		static void addWindow(GUI::Window::IWindow* window) {
			window->setCloseEvent(
				new GUI::Events::EventUI(
					S_EVENT_LAMBDA(info) {
						auto win = (GUI::Window::IWindow*)info->getSender();
						removeWindow(win);
						delete win;
					}
				)
			);
			m_windows.push_back(window);
		}

		static void removeWindow(GUI::Window::IWindow* window) {
			m_windows.remove(window);
			if (m_windows.size() == 0) {
				setVisibleForAll(false);
			}
		}

		static void setVisibleForAll(bool state) {
			m_shown = state;
		}

		static bool isVisible() {
			return m_shown;
		}

		static void RenderAllWindows() {
			if (!m_shown)
				return;
			for (auto it : m_windows) {
				it->show();
			}
		}
	private:
		inline static std::list<GUI::Window::IWindow*> m_windows;
		inline static bool m_shown = true;
	};

	void init(void* hwnd, ID3D11Device* device, ID3D11DeviceContext* ctx)
	{
		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGui_ImplWin32_Init(hwnd);
		ImGui_ImplDX11_Init(device, ctx);
		ImGui::StyleColorsDark();
		//GUI::Font::init();
		GUI::StyleThemes::Standart();
	}

	void render()
	{
		if (!WinManager::isVisible())
			return;

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		//ImGui::PushFont(GUI::Font::Tahoma);
		WinManager::RenderAllWindows();
		GUI::Events::EventUI::handleEvents();
		//ImGui::PopFont();

		ImGui::Render();
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
	}
};