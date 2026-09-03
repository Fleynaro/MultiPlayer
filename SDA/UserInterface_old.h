#pragma once
#include "Shared/GUI/Items/Items.h"
#include "Shared/GUI/Items/StyleThemes.h"
#include "Shared/GUI/Items/IWidget.h"
#include "WindowManager.h"


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