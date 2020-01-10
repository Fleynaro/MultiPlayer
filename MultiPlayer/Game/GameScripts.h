#pragma once


#include "main.h"
#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"
#include "Game/ScriptEngine/Natives/NativeGroup_GAMEPLAY.h"



class GameScript
{
public:
	GameScript(std::string name)
	{
		m_name = name;
		m_hash = std::hash<std::string>()(m_name);
	}

	//get hash(id) of the script
	std::size_t getHash()
	{
		return m_hash;
	}

	//get script name
	std::string getName()
	{
		return m_name;
	}

	//increase counter of sctipt calls
	void call()
	{
		m_callCount++;
	}

	//get count of script calls
	unsigned long long getCallCount()
	{
		return m_callCount;
	}

	//enable the script
	void enable()
	{
		m_enabled = true;
	}

	//disable the script
	void disable()
	{
		m_enabled = false;
	}

	//terminate the script
	void terminate()
	{
		SE::GAMEPLAY::TERMINATE_ALL_SCRIPTS_WITH_THIS_NAME(
			getName().c_str()
		);
		m_terminated = true;
	}

	//check the script enabled
	bool isEnabled()
	{
		return m_enabled;
	}

	//check the script terminated
	bool isTerminated()
	{
		return m_terminated;
	}
private:
	std::string m_name;
	std::size_t m_hash;
	unsigned long long m_callCount = 0;
	bool m_enabled = true;
	bool m_terminated = false;
};



class GameScripts : public IGameStaticHooked
{
	friend class GameScriptsHook_Gen;
public:
	//structure Data for executeScriptHook
	class Data : public Memory::IDynStructure<Data>
	{
	public:
		enum FIELD {
			scriptName
		};

		static void init() {
			setFieldOffset(scriptName, 0xD0);
		}

		Data(Memory::Handle base) : IDynStructure(base) {}

		std::string getScriptName() {
			return getFieldPtr<char*>(scriptName);
		}
	};

	//disable all native game scripts
	static void disableAllScripts()
	{
		for (auto script : m_scriptList) {
			script->disable();
		}
	}

	//disable all native game scripts
	static void terminateDisabledScripts()
	{
		for (auto script : m_scriptList) {
			if (!script->isEnabled() && !script->isTerminated()) {
				script->terminate();
			}
		}
	}

	//get a native game script by name
	static GameScript* getScriptByName(const std::string name)
	{
		std::size_t hash = std::hash<std::string>()(name);
		for (auto script : m_scriptList) {
			if (hash == script->getHash()) {
				return script;
			}
		}
		return nullptr;
	}

	//get the current executed native game script
	static GameScript* getCurrentExecutedScript() {
		return m_curExeGameScript;
	}

	//check the script executed now
	static bool isCurrentExecutedScript(const std::string name) {
		return getCurrentExecutedScript() == getScriptByName(name);
	}
private:
	using scriptList = std::vector<GameScript*>;
	inline static GameScript *m_curExeGameScript;
	static scriptList m_scriptList;

	static int executeScriptHook(void* pData)
	{
		Data data(pData);
		GameScript* script = getScriptByName(
			Generic::String::ToLower(data.getScriptName())
		);

		if (script != nullptr)
		{
			script->call();
			if (!script->isEnabled())
				return 0;
		}

		setCurrentExecutedScript(script);
		int result = executeScript.executeOrigFunc(pData);
		setCurrentExecutedScript(nullptr);
		return result;
	}
	inline static Memory::FunctionHook<decltype(executeScriptHook)> executeScript;

	//set the current executed native game script
	static void setCurrentExecutedScript(GameScript* script) {
		m_curExeGameScript = script;
	}
};




class GameScriptsHook_Gen : public IGameHook, public ISingleton<GameScriptsHook_Gen>
{
public:
	void Install()
	{
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 80 B9 ?? ?? 00 00 00 8B FA 48 8B D9 ?? ?? 8B"),
				&executeScript
			)
		);
	}

	static void executeScript(Memory::FoundPattern &pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameScripts::executeScript = Memory::FunctionHook<decltype(GameScripts::executeScriptHook)>(pattern.getResult());
		GameScripts::executeScript.setFunctionHook(GameScripts::executeScriptHook);
		GameScripts::executeScript.hook();
	}

	void Remove()
	{
		GameScripts::executeScript.disable();
	}
};