#pragma once
#include "GUI/Items/Items.h"
#include "GUI/Items/StyleThemes.h"
#include "GUI/Items/IWindow.h"
#include "GUI/Items/IWidget.h"

using namespace GUI::Window;

class WindowManager
{
public:
	WindowManager()
	{}

	void addWindow(GUI::Window::IWindow* window) {
		window->setCloseEvent(
			new GUI::Events::EventUI(EVENT_LAMBDA(info) {
				auto win = (GUI::Window::IWindow*)info->getSender();
				removeWindow(win);
				delete win;
			})
		);
		m_windows.push_back(window);
	}

	void removeWindow(GUI::Window::IWindow* window) {
		m_windows.remove(window);
		if (m_windows.size() == 0) {
			setVisibleForAll(false);
		}
	}

	void setVisibleForAll(bool state) {
		m_shown = state;
	}

	bool isVisible() {
		return m_shown;
	}

	void render() {
		if (!m_shown)
			return;
		for (auto it : m_windows) {
			it->show();
		}
	}
private:
	std::list<GUI::Window::IWindow*> m_windows;
	bool m_shown = true;
};

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

class UserInterface
{
public:
	UserInterface()
	{
		m_windowManager = new WindowManager;
	}

	void init() {
		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGui_ImplWin32_Init(m_hwnd);

		ID3D11Device* pDevice = NULL;
		ID3D11DeviceContext* pContext = NULL;
		m_pSwapChain->GetDevice(__uuidof(pDevice), (void**)& pDevice);
		pDevice->GetImmediateContext(&pContext);
		ImGui_ImplDX11_Init(pDevice, pContext);

		ImGui::StyleColorsDark();
		GUI::StyleThemes::Standart();

		initWndProcCallback();
	}

	void render() {
		if (!m_firstInit) {
			init();
			m_firstInit = true;
		}

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		getWindowManager()->render();
		GUI::Events::EventUI::handleEvents();

		ImGui::Render();
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
	}

	WindowManager* getWindowManager() {
		return m_windowManager;
	}

	void setWindow(HWND hwnd) {
		m_hwnd = hwnd;
		m_firstInit = false;
	}

	void setSwapChain(IDXGISwapChain* pSwapChain) {
		m_pSwapChain = pSwapChain;
		m_firstInit = false;
	}

	void initWndProcCallback() {
		m_origWndProc = (WNDPROC)SetWindowLongPtr(m_hwnd, GWLP_WNDPROC, (LONG_PTR)WndProc);
	}

	static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam);
		return CallWindowProc(m_origWndProc, hwnd, uMsg, wParam, lParam);
	}
private:
	bool m_firstInit = false;
	WindowManager* m_windowManager;
	HWND m_hwnd = nullptr;
	IDXGISwapChain* m_pSwapChain = nullptr;
	inline static WNDPROC m_origWndProc = nullptr;
};