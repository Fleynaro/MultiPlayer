#pragma once




#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Game/GameEvent.h"
#include "Game/GameUpdate.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"
#include "Utility/Stat.h"

#include "IGameHashes.h"

//all native groups
#include "Natives/NativeGroup_PLAYER.h"
#include "Natives/NativeGroup_ENTITY.h"
#include "Natives/NativeGroup_PED.h"
#include "Natives/NativeGroup_VEHICLE.h"
#include "Natives/NativeGroup_OBJECT.h"
#include "Natives/NativeGroup_WEAPON.h"
#include "Natives/NativeGroup_WATER.h"
#include "Natives/NativeGroup_FIRE.h"
#include "Natives/NativeGroup_STATS.h"
#include "Natives/NativeGroup_ROPE.h"
#include "Natives/NativeGroup_WORLDPROBE.h"
#include "Natives/NativeGroup_TIME.h"
#include "Natives/NativeGroup_AI.h"
#include "Natives/NativeGroup_GAMEPLAY.h"
#include "Natives/NativeGroup_AUDIO.h"
#include "Natives/NativeGroup_CAM.h"
#include "Natives/NativeGroup_UI.h"
#include "Natives/NativeGroup_GRAPHICS.h"
#include "Natives/NativeGroup_STREAMING.h"
#include "Natives/NativeGroup_SYSTEM.h"





class GameEventScriptExeMessage : public IGameEventMessage
{
public:
	GameEventScriptExeMessage() : IGameEventMessage(GameEventMessageId::GAME_SCRIPT_EXECUTE) {}
};

class IGameEventScriptExecute : public IGameEventHandler
{
public:
	IGameEventScriptExecute() = default;

	bool filter(IGameEventMessage::Type &message) override {
		if (message->getMessageId() == GameEventMessageId::GAME_SCRIPT_EXECUTE)
			return true;
		return false;
	}

	void callback(IGameEventMessage::Type &message, bool& result, bool& doContinue) override
	{
		if (!filter(message))
			return;

		Main();
	}
	virtual void Main() = 0;
};

//class where you can execute game scripts(spawn vehicles, peds, play audio, ...)
class IGameScriptContext
	: public IGameEventScriptExecute
{
protected:
	//place your script code here
	virtual void OnTick() = 0;
	//init game script
	virtual void OnInit() {};

	//here useful place a code of entering any context
	virtual void OnExecuteFiber() {
		ExecuteFiber();
	};

	//it is a fiber and through it any message go to you
	void ExecuteFiber() {
		if (!m_init) {
			m_proxyAgregator = new GameEventProxyMessageAgregator;

			OnInit();
			m_init = true;
		}
		getProxyAgregator()->sendMessages();
		OnTick();
		switchToMainFiber();
	}
private:
	bool m_init = false;
	LPVOID m_fiber = nullptr;
	std::size_t m_wakeAt = 0;
	GameEventProxyMessageAgregator* m_proxyAgregator = nullptr;

	//entry point called when the next game script executing iteration begins
	void Main() override
	{
		if (!m_init) {
			fiberInit();
		}

		if (getFiber() != nullptr) {
			if (!isSleeping()) {
				execute();
			}
			else {
				getProxyAgregator()->clear();
			}
		}
	}

	//create a context(separate executing context)
	void fiberInit()
	{
		if (getMainFiber() == nullptr) {
			convertToFiber();
		}
		m_fiber = CreateFiber(NULL, [](LPVOID handler)
			{
				while (1)
				{
					auto instance = reinterpret_cast<IGameScriptContext*>(handler);
					instance->OnExecuteFiber();
				}
			}, this);
	}

	//go to the script context
	void execute() {
		SwitchToFiber(getFiber());
	}

	inline static HANDLE m_mainFiber;
	static void convertToFiber() {
		m_mainFiber = IsThreadAFiber() ? GetCurrentFiber() : ConvertThreadToFiber(NULL);
	}

	using ConsoleLogList = std::list<
		std::pair<
			std::chrono::time_point<std::chrono::system_clock>,
			std::string
		>
	>;
	ConsoleLogList m_consoleLog;
public:
	virtual ~IGameScriptContext() {}

	enum class Type {
		Standart,
		JavaScript,
		Lua
	};

	virtual Type getType() {
		return Type::Standart;
	}

	struct : Stat::Id
	{
	} m_info;

	GameEventProxyMessageAgregator* getProxyAgregator() {
		return m_proxyAgregator;
	}

	//get the main context
	static HANDLE getMainFiber() {
		return m_mainFiber;
	}

	//go to the main context
	static void switchToMainFiber() {
		SwitchToFiber(getMainFiber());
	}

	//get fiber
	LPVOID getFiber() {
		return m_fiber;
	}

	//is the script sleeping
	bool isSleeping() {
		return timeGetTime() < m_wakeAt;
	}

	//sleep
	void sleep(std::size_t ms, bool switchToMain = true) {
		m_wakeAt = timeGetTime() + ms;
		if (switchToMain) {
			switchToMainFiber();
		}
	}

	//skip the current game frame
	void yield() {
		sleep(0);
	}

	//add log message
	void addConsoleMessage(std::string message) {
		getConsoleLog().push_back(
			std::make_pair(
				std::chrono::system_clock::now(),
				message
			)
		);
		if (getConsoleLog().size() > 30) {
			getConsoleLog().erase(getConsoleLog().begin());
		}
	}

	//get console log list
	ConsoleLogList& getConsoleLog() {
		return m_consoleLog;
	}
	
	//clear console log
	void clearConsoleLog() {
		m_consoleLog.clear();
	}

	virtual IGameScriptContext* getCopyInstance() = 0;
};



class GameScriptEngine : public IGameEventPublisher<IGameEventScriptExecute>, public IGameStaticHooked
{
	friend class GameScriptEngineHook_Gen;
public:
	static void initNatives()
	{
		if (!isAllNativesRegistered())
			return;
		SE::PLAYER::initNatives();
		SE::ENTITY::initNatives();
		SE::PED::initNatives();
		SE::VEHICLE::initNatives();
		SE::OBJECT::initNatives();
		SE::STATS::initNatives();
		SE::WEAPON::initNatives();
		SE::TIME::initNatives();
		SE::WORLDPROBE::initNatives();
		SE::WATER::initNatives();
		SE::FIRE::initNatives();
		SE::AI::initNatives();
		SE::GAMEPLAY::initNatives();
		SE::AUDIO::initNatives();
		SE::CAM::initNatives();
		SE::UI::initNatives();
		SE::GRAPHICS::initNatives();
		SE::STREAMING::initNatives();
		SE::SYSTEM::initNatives();
	}

	static void init()
	{
		addNativeGroup<SE::PLAYER>("PLAYER");
		addNativeGroup<SE::ENTITY>("ENTITY");
		addNativeGroup<SE::PED>("PED");
		addNativeGroup<SE::VEHICLE>("VEHICLE");
		addNativeGroup<SE::OBJECT>("OBJECT");
		addNativeGroup<SE::STATS>("STATS");
		addNativeGroup<SE::WEAPON>("WEAPON");
		addNativeGroup<SE::TIME>("TIME");
		addNativeGroup<SE::WORLDPROBE>("WORLDPROBE");
		addNativeGroup<SE::WATER>("WATER");
		addNativeGroup<SE::FIRE>("FIRE");
		addNativeGroup<SE::AI>("AI");
		addNativeGroup<SE::GAMEPLAY>("GAMEPLAY");
		addNativeGroup<SE::AUDIO>("AUDIO");
		addNativeGroup<SE::CAM>("CAM");
		addNativeGroup<SE::UI>("UI");
		addNativeGroup<SE::GRAPHICS>("GRAPHICS");
		addNativeGroup<SE::STREAMING>("STREAMING");
		addNativeGroup<SE::SYSTEM>("SYSTEM");
	}

	template<typename NativeGroupClass>
	static void addNativeGroup(std::string groupName) {
		//getNativeGroups()[groupName] = std::list<IGameNative*>;
		for (IGameNative* it : NativeGroupClass::getNatives()) {
			getNativeGroups()[groupName].push_back(it);
		}
	}

	static std::map<std::string, std::list<IGameNative*>>& getNativeGroups() {
		return m_natives;
	}

	static bool isAllNativesRegistered() {
		return GameHashNativeHandler::getList().getCount() != 0;
	}

	//register a script context
	static void registerScriptExecutingContext(IGameScriptContext* context) {
		getContexts().push_back(context);
		context->addConsoleMessage("the context has been registered.");
	}

	//unregister a script context
	static void unregisterScriptExecutingContext(IGameScriptContext* context) {
		getContexts().remove(context);
		context->addConsoleMessage("the context has been unregistered.");
	}

	//reload a script context
	static void reloadScriptExecutionContext(IGameScriptContext*& context) {
		auto newContext = context->getCopyInstance();
		if (newContext != nullptr) {
			GameScriptEngine::removeEventHandler(context);
			unregisterScriptExecutingContext(context);
			GameScriptEngine::addEventHandler(newContext);
			delete context;
			context = newContext;
			context->addConsoleMessage("the context has been reloaded.");
		}
	}

	static IGameScriptContext* getCurrentScriptExeContext() {
		if (!IsThreadAFiber())
			return nullptr;
		
		for (auto it : getContexts()) {
			if (it->getFiber() == GetCurrentFiber()) {
				return it;
			}
		}
		return nullptr;
	}

	static std::list<IGameScriptContext*>& getContexts() {
		return m_contexts;
	}
private:
	static inline std::map<std::string, std::list<IGameNative*>> m_natives;

	static void RegisterNativeHook(void* table, IGameNative::Hash hash, void* handler)
	{
		GameHashNativeHandler::getList().addHash(
			new GameHashNativeHandler(hash, handler)
		);
		RegisterNative.executeOrigFunc(table, hash, handler);
	}
	inline static Memory::FunctionHook<decltype(RegisterNativeHook)> RegisterNative;


	static void SleepHook(GameNativeScrContext* context)
	{
		sendEventToAll(
			IGameEventMessage::Type(new GameEventScriptExeMessage)
		);

		return Sleep.executeOrigFunc(context);
	}
	inline static Memory::FunctionHook<decltype(SleepHook)> Sleep;

	inline static std::list<IGameScriptContext*> m_contexts;
};



class GameScriptEngineHook_Gen : public IGameHook, public ISingleton<GameScriptEngineHook_Gen>
{
private:
	class Init : public IGameEventUpdate {
		bool OnInit() override {
			//GameScriptEngine::Sleep = 0x4EDE34FBADD967A6_handler;
			GameScriptEngine::Sleep = 0x4EDE34FBADD967A6_handler;
			GameScriptEngine::Sleep.setFunctionHook(GameScriptEngine::SleepHook);
			GameScriptEngine::Sleep.hook();
			return true;
		}
	};
public:
	void Install()
	{
		GameUpdate::addEventHandler(
			new Init
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 BA 9C 13 0A F4 62 B1 FF D0 48 8B CB E8 *?? ?? ?? ??"),
				&registerNative
			)
		);

	}

	static void registerNative(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameScriptEngine::RegisterNative = pattern.getResult().rip(4);
		GameScriptEngine::RegisterNative.setFunctionHook(GameScriptEngine::RegisterNativeHook);
		GameScriptEngine::RegisterNative.hook();
	}

	void Remove()
	{
	}
};