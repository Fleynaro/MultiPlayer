#pragma once



#include <chrono>
#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Game/GameEvent.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"







class GameEventUpdateMessage : public IGameEventMessage
{
public:
	GameEventUpdateMessage() : IGameEventMessage(GameEventMessage::GAME_UPDATE) {}
};

class GameEventInitMessage : public IGameEventMessage
{
public:
	GameEventInitMessage() : IGameEventMessage(GameEventMessage::GAME_INIT) {}
};

class IGameEventUpdate : public IGameEventHandler
{
public:
	IGameEventUpdate() = default;

	bool filter(IGameEventMessage::Type &message) override {
		if (message->getMessage() == GameEventMessage::GAME_INIT || message->getMessage() == GameEventMessage::GAME_UPDATE)
			return true;
		return false;
	}

	void callback(IGameEventMessage::Type &message) override
	{
		if (!filter(message))
			return;
		if (message->getMessage() == GameEventMessage::GAME_INIT)
			OnInit();
		
		OnUpdate();
	}
	virtual void OnUpdate() {};
	virtual void OnInit() {};
};



class GameUpdate : public IGameEventPublisher<IGameEventUpdate>, public IGameStaticHooked
{
	friend class GameUpdateHook_Gen;
public:
	static void MainUpdateHook(DWORD64 p1)
	{
		static bool init = false;
		if (!init) {
			sendEventToAll(
				IGameEventMessage::Type(new GameEventInitMessage)
			);
			init = true;
		}
		
		sendEventToAll(
			IGameEventMessage::Type(new GameEventUpdateMessage)
		);

		counter();
		MainUpdate.executeOrigFunc(p1);
	}

	static std::size_t getFPS()
	{
		return (std::size_t)ceil(
			1000.0 / deltaCallTime.count()
		);
	}
private:
	using ms = std::chrono::duration<double, std::milli>;
	inline static ms deltaCallTime;
	inline static Memory::FunctionHook<decltype(MainUpdateHook)> MainUpdate;

	//count fps
	static void counter()
	{
		auto curTimestamp = std::chrono::steady_clock::now();
		static decltype(curTimestamp) preTimestamp;

		deltaCallTime = std::chrono::duration_cast<ms>(
			curTimestamp - preTimestamp
		);
		preTimestamp = curTimestamp;
	}
};



class GameUpdateHook_Gen : public IGameHook, public ISingleton<GameUpdateHook_Gen>
{
public:
	void Install()
	{
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 83 EC 28 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 *?? ?? ?? ?? B9 05 00 00 00 E8"),
				&MainUpdate
			)
		);
	}

	static void MainUpdate(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameUpdate::MainUpdate = pattern.getResult().rip(4);
		GameUpdate::MainUpdate.setFunctionHook(GameUpdate::MainUpdateHook);
		GameUpdate::MainUpdate.hook();
	}

	void Remove()
	{
	}
};