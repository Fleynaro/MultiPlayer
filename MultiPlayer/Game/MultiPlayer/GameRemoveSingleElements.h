#pragma once






#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Game/GameScripts.h"
#include "Game/GameUpdate.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"



class GameRemoveSingleElements : public IGameStaticHooked
{
	friend class GameRemoveSingleElementsHook_Gen;
public:
	inline static Memory::Function<void()> DisableSpawnVehicle;
private:
	class Init : public IGameEventUpdate {
		void OnInit() override {
			GameRemoveSingleElements::DisableSpawnVehicle();
		}
	};

	//spawn
	inline static Memory::FunctionHook<void()> SpawnPeds1;
	inline static Memory::FunctionHook<void()> SpawnVehicleOnce; //cars spawned when the player has spawn
	inline static Memory::FunctionHook<void(DWORD64 p1, DWORD64 p2, DWORD64 p3)> SpawnFiremans;

	//other
	inline static Memory::FunctionHook<void()> FakeVehicleStreaming; //fake vehicles spawned a far away from the player
	inline static Memory::FunctionHook<DWORD64(int p1)> SpecialSkill;
	inline static Memory::FunctionHook<void(void* p1, DWORD64 p2, DWORD64 p3, DWORD64 p4)> WantedUpdate;
	inline static Memory::FunctionHook<void(void* p1, DWORD64 p2, DWORD64 p3, DWORD64 p4, BYTE p5, int p6, DWORD64 p7, BYTE p8)> PoliceChaise;
	inline static Memory::FunctionHook<void(DWORD64 p1, float* pos, DWORD64 p3, int* p4, DWORD32 p5)> PoliceUpdate;



	//spawn peds
	static DWORD64 SpawnPeds2_hook(DWORD64 lParm1, int uParm2, DWORD64 uParm3, int uParm4)
	{
		if (uParm2 == 4 && uParm4 == 1) {
			return 1;
		}
		return SpawnPeds2.executeOrigFunc(lParm1, uParm2, uParm3, uParm4);
	}
	inline static Memory::FunctionHook<decltype(SpawnPeds2_hook)> SpawnPeds2;
	
	//spawn vehicles(CreateVehicle)
	static DWORD64 SpawnVehicle2_hook(DWORD64 p1, float pos[4], DWORD64 p3, bool p4, bool p5, byte p6)
	{
		if (GameScripts::isCurrentExecutedScript("vehicle_gen_controller")) {
			return 0;
		}
		return SpawnVehicle2.executeOrigFunc(p1, pos, p3, p4, p5, p6);
	}
	inline static Memory::FunctionHook<decltype(SpawnVehicle2_hook)> SpawnVehicle2;
};



class GameRemoveSingleElementsHook_Gen : public IGameHook, public ISingleton<GameRemoveSingleElementsHook_Gen>
{
public:
	void Install()
	{
		GameUpdate::addEventHandler(
			new GameRemoveSingleElements::Init
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("FF FF E8 ?? ?? ?? ?? 45 33 FF 41 BC 01 00 00 00 84"),//C0 74 09 44 01
				&SpawnPeds1
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("85 D2 0F 88 BA 00 00 00 B8 01 00 00 00 75"),//0E 44 3B C8
				&SpawnPeds2
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(//80 8B ?? ??
				Memory::Pattern("00 00 20 C7 83 ?? ?? 00 00 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 *??"),
				&DisableSpawnVehicle
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(//48 89 DC 48 89 0C 24 48 8B 1C 24 48
				Memory::Pattern("8D 64 24 08 8B 0A 48 83 C2 08 E9 ?? ?? ?? ?? E8 *??"),
				&SpawnVehicle2
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("00 E8 *?? ?? ?? ?? 8B 05 ?? ?? ?? ?? A8 01 0F 85 ?? ?? ?? ?? 0F 28 05"),
				&SpawnVehicleOnce
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 83 EC 50 41 8B 80 ?? 00 00 00 41 BF 04 00 00 00 4D 8B"),//E8 41     -19
				&SpawnFiremans
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("E8 *?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 74 3D 80 3D"), //?? ?? ?? ?? 00 65 48 8B
				&FakeVehicleStreaming
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("83 F8 FF 74 0E 8B C8 E8 *?? ?? ?? ?? 48 89 83"), //?? ?? 00 00 48 83 C4 20 5B C3
				&SpecialSkill
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 8B CF E8 *?? ?? ?? ?? 33 DB 45 84 E4 74 4D"),//8A 87 ??
				&WantedUpdate
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(//45 33 C9
				Memory::Pattern("8B D7 89 5C 24 28 C6 44 24 20 01 E8 *?? ?? ?? ??"),
				&PoliceChaise
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(//45 33 C9
				Memory::Pattern("0F 29 45 E7 44 88 7C 24 20 E8 *?? ?? ?? ?? BA 00"), //02 00 00 48
				&PoliceUpdate
			)
		);
	}

	static void SpawnFiremans(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::SpawnFiremans = pattern.getResult().sub(19);
		GameRemoveSingleElements::SpawnFiremans.hookWithNothing();
	}

	static void FakeVehicleStreaming(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::FakeVehicleStreaming = pattern.getResult().rip(4);
		GameRemoveSingleElements::FakeVehicleStreaming.hookWithNothing();
	}

	static void SpecialSkill(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::SpecialSkill = pattern.getResult().rip(4);
		GameRemoveSingleElements::SpecialSkill.hookWithNothing();
	}

	static void WantedUpdate(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::WantedUpdate = pattern.getResult().rip(4);
		GameRemoveSingleElements::WantedUpdate.hookWithNothing();
	}

	static void PoliceChaise(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::PoliceChaise = pattern.getResult().rip(4);
		GameRemoveSingleElements::PoliceChaise.hookWithNothing();
	}

	static void PoliceUpdate(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::PoliceUpdate = pattern.getResult().rip(4);
		GameRemoveSingleElements::PoliceUpdate.hookWithNothing();
	}

	static void SpawnPeds1(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::SpawnPeds1 = pattern.getResult().sub(94);
		GameRemoveSingleElements::SpawnPeds1.hookWithNothing();
	}

	static void SpawnPeds2(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::SpawnPeds2 = pattern.getResult();
		GameRemoveSingleElements::SpawnPeds2.setFunctionHook(GameRemoveSingleElements::SpawnPeds2_hook);
		GameRemoveSingleElements::SpawnPeds2.hook();
	}

	static void DisableSpawnVehicle(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::DisableSpawnVehicle = pattern.getResult().rip(4);
	}

	static void SpawnVehicle2(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::SpawnVehicle2 = pattern.getResult().rip(4);
		GameRemoveSingleElements::SpawnVehicle2.setFunctionHook(GameRemoveSingleElements::SpawnVehicle2_hook);
		GameRemoveSingleElements::SpawnVehicle2.hook();
	}

	static void SpawnVehicleOnce(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameRemoveSingleElements::SpawnVehicleOnce = pattern.getResult().rip(4);
		GameRemoveSingleElements::SpawnVehicleOnce.hookWithNothing();
	}

	void Remove()
	{
	}
};