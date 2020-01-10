#pragma once










#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"




class GameCursorPointer : public IGameStaticHooked
{
	friend class GameCursorPointerHook_Gen;
public:

	static void UpdateVisibleHook(bool state)
	{
		if (m_show) {
			state = true;
		}
		UpdateVisible.executeOrigFunc(state);
	}
	inline static Memory::FunctionHook<decltype(UpdateVisibleHook)> UpdateVisible;
	

	//make cursor not to return back and thus not hide
	static void setNotReturnBack(bool state)
	{
		m_notRetBack = state;
		ShowCursor(state);
	}
	
	//show or hide cursor
	static void show(bool state) {
		m_show = state;
		ShowCursor(state);
		UpdateVisibleHook(state);
	}
private:
	inline static bool m_show;
	inline static Memory::Object<bool> m_notRetBack;
};



class GameCursorPointerHook_Gen : public IGameHook, public ISingleton<GameCursorPointerHook_Gen>
{
public:
	void Install()
	{
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("74 07 33 C9 E8 *?? ?? ?? ?? 38 1D ?? ?? ?? ?? 0F 84 E7"),
				&UpdateVisible
			)
		);
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("FF 40 38 35 *?? ?? ?? ?? 75 12 40 38 35 ?? ?? ?? ?? 74 09 40 38 35"),
				&ReturnBackVar
			)
		);
	}

	static void UpdateVisible(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameCursorPointer::UpdateVisible = Memory::FunctionHook<decltype(GameCursorPointer::UpdateVisibleHook)>(pattern.getResult().rip(4));
		GameCursorPointer::UpdateVisible.setFunctionHook(GameCursorPointer::UpdateVisibleHook);
		GameCursorPointer::UpdateVisible.hook();
	}

	static void ReturnBackVar(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameCursorPointer::m_notRetBack = pattern.getResult().rip(4);
	}

	void Remove()
	{
	}
};