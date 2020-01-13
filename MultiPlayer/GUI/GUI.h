#pragma once

#include "Core/UserKeyboardList.h"

#include "Game/DirectX/Direct3D11.h"
#include "Game/GameInput.h"

#include <GUI/Items/StyleThemes.h>
#include "Windows/ContextManagerWin.h"
#include "Widgets/PopupContextWindow.h"

#include "Game/GameAppInfo.h"

#include <Utility/DebugView.h>

#include <SDA/SdaInterface.h>


extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

namespace GUI
{
	inline static SdaInterface* sda = nullptr;

	class GameContext : public IGameScriptContext
	{
	public:
		IGameScriptContext* getCopyInstance() override {
			return new GameContext;
		}

		void OnInit() override
		{
			GameScriptEngine::registerScriptExecutingContext(this);
		}

		void OnTick() override
		{
			Events::EventSDK::handleEvents();
		}
	};

	class Draw;
	namespace Window
	{
		class WinManager
		{
			friend class GUI::Draw;
		public:

			static void registerWindows()
			{
				addWindow(new GUI::Window::ContextManager);
			}

			static void addWindow(IWindow* window) {
				window->setCloseEvent(
					new Events::EventUI(
						S_EVENT_LAMBDA(info) {				
							auto win = (IWindow*)info->getSender();
							removeWindow(win);
							delete win;
						}
					)
				);
				m_windows.push_back(window);
			}

			static void removeWindow(IWindow* window) {
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
		private:
			inline static std::list<IWindow*> m_windows;
			inline static bool m_shown = true;

			static void RenderAllWindows() {
				if (!m_shown)
					return;
				for (auto it : m_windows) {
					it->show();
				}
			}
		};
	};


	class Draw : public IGameEventD3D_Present
	{
	public:
		Draw()
		{
			IMGUI_CHECKVERSION();
			ImGui::CreateContext();
			ImGui_ImplWin32_Init(GameInput::m_hWindow);
			ImGui_ImplDX11_Init(Direct3D11::getDevice(), Direct3D11::getDeviceContext());
			ImGui::StyleColorsDark();
			Font::init(GameAppInfo::GetInstancePtr()->getDLL());
			GUI::StyleThemes::Standart();
		}

		void OnPresent(UINT SyncInterval, UINT Flags) override
		{
			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();
			ImGui::NewFrame();
			
			ImGui::PushFont(Font::Tahoma);
			Window::WinManager::RenderAllWindows();
			Widget::PopupContextWindow::Render();
			Events::EventUI::handleEvents();
			//ImGui::ShowStyleEditor();
			ImGui::PopFont();

			ImGui::Render();
			ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

			if (sda != nullptr) {
				sda->render();
			}
		}
	};

	
	class Input : public IGameEventInput
	{
	public:
		bool anyAfter(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam, bool& doContinue) override
		{
			if (Window::WinManager::isVisible()) {
				ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam);
				doContinue = false;
				return true;
			}
			return true;
		}

		void keyUp(KEY keyCode) override
		{
			if (keyCode == KeyCode::F2)
			{
				GameExit::Exit();
			}

			if (keyCode == KeyCode::F3 && sda == nullptr)
			{
				DebugOutput("try loading SDA.dll");
				HINSTANCE dll = LoadLibrary("FastLoader/SDA.dll");
				if (dll != NULL) {
					sda = getSdaInterface(dll);
					if (sda != nullptr) {
						sda->setWindow(GameInput::m_hWindow);
						sda->setSwapChain(Direct3D11::getSwapChain());
						sda->start();
					}
				}
				DebugOutput("SDA.dll = " + std::to_string((std::uintptr_t)dll));
			}

			if (keyCode == KeyCode::F4)
			{
				static bool init = false;
				if (!init) {
					Direct3D11::addEventHandler(new Draw);
					Window::WinManager::registerWindows();
					GameCursorPointer::show(true);
					init = true;
					return;
				}

				static bool show = true;
				Window::WinManager::setVisibleForAll(show ^= 1);
				SE::PLAYER::SET_PLAYER_CONTROL(SE::PLAYER::PLAYER_ID(), !show, 0);
				GameCursorPointer::show(show);

			}

			if (keyCode == KeyCode::Shift && m_lAltPressed
				|| keyCode == KeyCode::Space && m_lCtrlPressed
				|| keyCode == KeyCode::F5) {
				UserKeyboardList::switchToNext();
			}
		}
	};
};