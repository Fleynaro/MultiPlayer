#pragma once

#include "GUI/Items/Items.h"
#include "GUI/Items/StyleThemes.h"
#include "GUI/Items/IWindow.h"
#include "GUI/Items/IWidget.h"

using namespace GUI::Window;


class UI
{
public:
	UI() {
	
	}

	class WinManager
	{
	public:
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