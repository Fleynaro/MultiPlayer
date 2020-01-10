#pragma once




#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"









class GameExit : public IGameStaticHooked
{
	friend class GameExitHook_Gen;
public:
	enum Code {
		EXIT = 0xF
	};

	//exit from game (ExitProcess called)
	static void Exit() {
		ExitCode = EXIT;
		IsNeedExit();
	}
private:
	inline static Memory::Function<void()> IsNeedExit;
	inline static Memory::Object<byte> ExitCode;
};



class GameExitHook_Gen : public IGameHook, public ISingleton<GameExitHook_Gen>
{
public:
	void Install()
	{
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 89 44 24 20 88 44 24 2F E8 *?? ?? ?? ?? 4C 8D 4C 24 20"), //45 33 C0 33 D2
				&IsNeedExit
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 81 EC 60 01 00 00 E8 ?? ?? ?? ?? 33 F6 48 8D 3D *?? ?? ?? ??"), //84 C0
				&ExitCode
			)
		);
	}

	static void IsNeedExit(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameExit::IsNeedExit = pattern.getResult().rip(4);
	}

	static void ExitCode(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameExit::ExitCode = pattern.getResult().rip(4);
	}

	void Remove()
	{
	}
};