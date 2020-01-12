#pragma once



#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Game/GameEvent.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"
#include "Utility/VirtualKeyCodes.h"




class GameEventInputMessage : public IGameEventMessage
{
public:
	HWND m_hwnd;
	UINT m_uMsg;
	WPARAM m_wParam;
	LPARAM m_lParam;
	GameEventInputMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
		: m_hwnd(hwnd), m_uMsg(uMsg), m_wParam(wParam), m_lParam(lParam),
		IGameEventMessage(GameEventMessageId::GAME_INPUT)
	{}
};

class IGameEventInput : public IGameEventHandler
{
public:
	using KEY = WPARAM;

	IGameEventInput() = default;

	bool filter(IGameEventMessage::Type &message) override {
		if (message->getMessageId() == GameEventMessageId::GAME_INPUT)
			return true;
		return false;
	}

	void callback(IGameEventMessage::Type &message, bool& result, bool& doContinue) override
	{
		if (!filter(message))
			return;

		auto mes = (GameEventInputMessage*)message.get();
		result = anyBefore(mes->m_hwnd, mes->m_uMsg, mes->m_wParam, mes->m_lParam, doContinue);
		m_extended = (mes->m_lParam & (1 << 24)) != 0;

		switch (mes->m_uMsg)
		{
			//https://docs.microsoft.com/ru-ru/windows/win32/inputdev/wm-keyup
		case WM_KEYUP:
		{
			keyUp(mes->m_wParam);
			if (mes->m_wParam == KeyCode::Shift) {
				m_lShiftPressed = false;
			}
			else if (mes->m_wParam == KeyCode::Control) {
				m_lCtrlPressed = false;
			}
			break;
		}
		case WM_KEYDOWN:
		{
			keyDown(mes->m_wParam);
			if (mes->m_wParam == KeyCode::Shift) {
				m_lShiftPressed = true;
			}
			else if (mes->m_wParam == KeyCode::Control) {
				m_lCtrlPressed = true;
			}
			break;
		}

			//https://docs.microsoft.com/ru-ru/windows/win32/inputdev/wm-lbuttondown
		case WM_LBUTTONDBLCLK:
			mLeftBtnDblClick();
			break;
		case WM_RBUTTONDBLCLK:
			mRightBtnDblClick();
			break;
		case WM_LBUTTONUP:
			mLeftBtnUp();
			break;
		case WM_LBUTTONDOWN:
			mLeftBtnDown();
			break;
		case WM_MBUTTONUP:
			mMiddleBtnUp();
			break;
		case WM_MBUTTONDOWN:
			mMiddleBtnDown();
			break;
		case WM_RBUTTONUP:
			mRightBtnUp();
			break;
		case WM_RBUTTONDOWN:
			mRightBtnDown();
			break;
		case WM_MOUSEMOVE:
			mMove(LOWORD(mes->m_lParam), HIWORD(mes->m_lParam));
			break;
		case WM_MOUSEWHEEL:
			mWheel(GET_WHEEL_DELTA_WPARAM(mes->m_wParam));
			break;

		case WM_SYSKEYUP:
		{
			if (mes->m_lParam & (1 << 29)) {
				m_lAltPressed = true;
				keyUp(mes->m_wParam);
				m_lAltPressed = false;
			}
			break;
		}
		}

		result = anyAfter(mes->m_hwnd, mes->m_uMsg, mes->m_wParam, mes->m_lParam, doContinue);
	}
	virtual void keyUp(KEY keyCode) {}
	virtual void keyDown(KEY keyCode) {}
	virtual void mLeftBtnDblClick() {}
	virtual void mRightBtnDblClick() {}
	virtual void mLeftBtnDown() {}
	virtual void mLeftBtnUp() {}
	virtual void mMiddleBtnDown() {}
	virtual void mMiddleBtnUp() {}
	virtual void mRightBtnDown() {}
	virtual void mRightBtnUp() {}
	virtual void mMove(short x, short y) {}
	virtual void mWheel(short delta) {}
	virtual bool anyBefore(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam, bool& doContinue) { return true; }
	virtual bool anyAfter(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam, bool& doContinue) { return true; }
protected:
	bool m_lAltPressed = false;
	bool m_lCtrlPressed = false;
	bool m_lShiftPressed = false;
	bool m_extended = false;
};


class GameInput : public IGameEventPublisher<IGameEventInput>, public IGameStaticHooked
{
	friend class GameInputHook_Gen;
public:
	//set origin windows proc
	static void setOrigWndProc(WNDPROC p) {
		m_origWndProc = p;
	}

	//get origin windows proc
	static WNDPROC getOrigWndProc() {
		return m_origWndProc;
	}

	inline static HWND m_hWindow;
private:
	inline static WNDPROC m_origWndProc;
	inline static Memory::FunctionHook<void()> m_keyBoardLayoutUpdate;


	//virtual key codes: https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
	//WndProc: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms633573(v%3Dvs.85)
	static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		if (!sendEventToAll(
			IGameEventMessage::Type(new GameEventInputMessage(hwnd, uMsg, wParam, lParam))
		)) {
			return 0;
		}

		return CallWindowProc(getOrigWndProc(), hwnd, uMsg, wParam, lParam);
	}
};


class GameInputHook_Gen : public IGameHook, public ISingleton<GameInputHook_Gen>
{
public:
	void Install()
	{
		CreateThread(NULL, NULL,
			(LPTHREAD_START_ROUTINE)MainThread,
			Memory::Module::main().getHMODULE(), NULL, NULL);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("FF FF E8 *?? ?? ?? ?? 44 8B C3 C1"),
				&KeyBoardLayoutUpdate
			)
		);
	}

	static DWORD WINAPI MainThread(HMODULE hModule)
	{
		while (GameInput::m_hWindow == NULL)
		{
			//find the main window to get HWND
			GameInput::m_hWindow = FindWindow("grcWindow", NULL);
			Sleep(100);
		}

		GameInput::setOrigWndProc(
			(WNDPROC)SetWindowLongPtr(GameInput::m_hWindow, GWLP_WNDPROC, (LONG_PTR)GameInput::WndProc)
		);
		return 0;
	}

	static void KeyBoardLayoutUpdate(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameInput::m_keyBoardLayoutUpdate = pattern.getResult().rip(4);
		GameInput::m_keyBoardLayoutUpdate.hookWithNothing();
	}

	void Remove()
	{
	}
};
