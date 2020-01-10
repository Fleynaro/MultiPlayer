#pragma once


#include "main.h"

#include "Game/GameVersionHook.h"
#include "Game/GameHookList.h"
#include "Game/GameException.h"
#include "Game/GameAppInfo.h"

#include "Utility/ISingleton.h"

#include "Core/ScriptLang/JavaScript/JavaScriptContext.h"
#include "Core/ScriptLang/Lua/LuaContext.h"

#include "UserKeyboardList.h"

#include "GUI/GUI.h"


//various launch mode - mp, single with mods, other
class Core : public ISingleton<Core>
{
public:
	Core()
	{
		if (MH_Initialize() != MH_OK) {
			//throw ex
			return;
		}

		defineGameVersion();
		installGameHooks();
		completeGameHooks();
		disableGameScripts();
		GUI_init();
		UserKeyboardList::init();
		GameScriptEngine::init();
		initScriptLangs();
	}

	void defineGameVersion()
	{
		m_hookManager = new GameVersionHook_141;
	}

	void installGameHooks()
	{
		GameScripts::InstallHook(
			getHookManager()->getGameScripts()
		);
		GamePool::InstallHook(
			getHookManager()->getPool()
		);
		GameObject::InstallHook(
			getHookManager()->getStructure()
		);
		GameUpdate::InstallHook(
			getHookManager()->getUpdate()
		);
		GameExit::InstallHook(
			getHookManager()->getExit()
		);
		GameInput::InstallHook(
			getHookManager()->getInput()
		);
		Direct3D11::InstallHook(
			getHookManager()->getD3D()
		);
		GameStartLoad::InstallHook(
			getHookManager()->getStartLoad()
		);
		GameCursorPointer::InstallHook(
			getHookManager()->getCursorPointer()
		);
		GameRemoveSingleElements::InstallHook(
			getHookManager()->getRemoveSingleElems()
		);

		GameScriptEngine::InstallHook(
			getHookManager()->getScriptEngine()
		);
		getHookManager()->setScriptEngineVersion();
	}

	void completeGameHooks() {
		GameHookList::m_cache = FS::File(
			GameAppInfo::GetInstancePtr()->getDllDirectory(),
			"offsets.json"
		);

		try {
			auto oldTimestamp = std::chrono::steady_clock::now();

			GameHookList::Complete();

			auto deltaCallTime = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - oldTimestamp
				);
			std::string message = "All patterns were found in " + deltaCallTime.count();
		}
		catch (GameHookException ex) {
			std::string message = "Hook error - not found pattern\n\nHook callback: " + ex.getDescription() + "\nPattern: " + ex.getFoundPattern()->getConstPattern().getStr();
			MessageBox(NULL, message.c_str(), NULL, MB_ICONEXCLAMATION | MB_OK);
			ExitProcess(2);
		}
	}

	void disableGameScripts()
	{
		//enable only needed game scripts
		GameScripts::disableAllScripts();
		GameScripts::getScriptByName("building_controller")->enable();
		GameScripts::getScriptByName("initial")->enable();
		GameScripts::getScriptByName("main")->enable();
		GameScripts::getScriptByName("standard_global_init")->enable();
		GameScripts::getScriptByName("pausemenu_map")->enable();
		GameScripts::getScriptByName("standard_global_reg")->enable();
		GameScripts::getScriptByName("startup")->enable();
		GameScripts::getScriptByName("startup_positioning")->enable();
		GameScripts::getScriptByName("vehicle_gen_controller")->enable();
		GameScripts::getScriptByName("main_persistent")->enable();
	}

	IGameVersionHook* getHookManager() {
		return m_hookManager;
	}

	void initScriptLangs()
	{
		SDK::EXPORT::buildAll();
		V8_init();
		Lua_init();
	}

	void V8_init()
	{
		JavaScript::init();
		v8::Isolate::Scope isolate_scope(JavaScript::getIsolate());

		auto scriptTestDir = getScriptDirectory().next("test");
		if (!scriptTestDir.createIfNotExists()) {
			//throw ex
		}

		return;

		auto js_exe_context = new JavaScriptContext(
			JavaScript::getIsolate(),
			std::shared_ptr<Script::Mod>(new Script::Mod(scriptTestDir))
		);
		GameScriptEngine::addEventHandler(
			js_exe_context
		);
	}

	void Lua_init()
	{
		auto scriptTestDir = getScriptDirectory().next("testLua");
		if (!scriptTestDir.createIfNotExists()) {
			//throw ex
		}

		auto state = new LuaState;
		auto mod = new Script::Mod(scriptTestDir);
		state->setLuaPath(
			mod->getDirectory().getPath() + "\\?.lua"
		);
		auto lua_exe_context = new LuaContext(
			std::shared_ptr<LuaState>(state),
			std::shared_ptr<Script::Mod>(mod)
		);
		GameScriptEngine::addEventHandler(
			lua_exe_context
		);
	}

	void GUI_init()
	{
		auto input = new GUI::Input;
		input->setPriority(GUI::Input::Priority::HIGH);
		GameInput::addEventHandler(input);
		GameScriptEngine::addEventHandler(new GUI::GameContext);
	}

	FS::Directory getScriptDirectory() {
		return GameAppInfo::GetInstancePtr()->getDllDirectory().next("scripts");
	}
private:
	IGameVersionHook* m_hookManager = nullptr;
};