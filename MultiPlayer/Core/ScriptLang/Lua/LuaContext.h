#pragma once

#include "Lua_include.h"
#include "../IScriptLangContext.h"


//wrapper of lua_State object
class LuaState
{
public:
	LuaState(lua_State* state)
		: m_state(state)
	{}
	LuaState() {
		m_state = luaL_newstate();
		luaL_openlibs(get());

		registerObjects();
	}
	~LuaState() {
		lua_close(get());
	}

	void registerObjects();
	int setLuaPath(std::string path);

	lua_State* get() {
		return m_state;
	}
private:
	lua_State* m_state;
};


//for events to listen them
class LuaListener
{
public:
	LuaListener(int idx)
		: m_idx(idx)
	{}
	~LuaListener() {
		IGameEventGenPublisher::removeEventHandler(m_listener);
		delete m_listener;
	}

	void setListener(IGameEventHandler* listener) {
		m_listener = listener;
		IGameEventGenPublisher::addEventHandler(m_listener);
	}

	int getIdx() {
		return m_idx;
	}
private:
	int m_idx;
	IGameEventHandler* m_listener = nullptr;
};


//separated fiber for executing lua code
class LuaContext : public IScriptLangContext
{
	friend class LuaState;
public:
	LuaContext(std::shared_ptr<LuaState> L, std::shared_ptr<Script::Mod> mod)
		: m_State(L), IScriptLangContext(mod)
	{}
	~LuaContext() {
		for (auto it : m_listeners) {
			delete it;
		}
	}

	Type getType() override {
		return Type::Lua;
	}

	IGameScriptContext* getCopyInstance() override {
		return new LuaContext(m_State, m_mod);
	}

	void OnInit() override
	{
		IScriptLangContext::OnInit();
		
		addConsoleMessage("try to execute the file " + getScriptMod()->getMainExecutionFile().getFullname() + "...");
		doFile(
			getScriptMod()->getMainExecutionFile()
		);

		addConsoleMessage("try to execute the entry " + getScriptMod()->getEntryFunction());
		executeEntryFunction(
			getScriptMod()->getEntryFunction()
		);
	}

	void addEventListener(std::string name, int eIdx) {
		auto lua_listener = new LuaListener(eIdx);
		m_listeners.push_back(lua_listener);

		auto listener = ScriptContextCallback::createEventListenerByName(this, lua_listener, name);
		if (listener == nullptr) {
			//throw ex
			return;
		}
		lua_listener->setListener(listener);
		listener->setPriority(Priority::LOW);
	}

	void OnAnyCallback(void* ptr, std::string name, Class::Adapter::ICallback* callback) override
	{
		//get the listener(callback)
		auto lua_listener = (LuaListener*)ptr;
		auto L = getState();
		lua_rawgeti(L, LUA_REGISTRYINDEX, lua_listener->getIdx());

		int top = lua_gettop(L);

		//push params to the callback
		int add = 0;
		if (lua_istable(L, -1)) {
			if (name.empty())
				lua_pushstring(L, "default");
			else lua_pushstring(L, name.c_str());

			lua_gettable(L, -2);
			if (!lua_isfunction(L, -1)) {
				lua_pop(L, 2);
				return;
			}

			lua_tocfunction(L, -1);
		}
		else if (lua_isfunction(L, -1)) {
			if (!name.empty()) {
				Class::Adapter::Lua_caller::PushValue(name, L);
				add = 1;
			}
		}
		else {
			lua_pop(L, 1);
			return;
		}

		int length;
		callback->Lua_pushParams(L, length);

		//execute callback
		lua_call(L, length + add, 0);
	}

	lua_State* getState() {
		return m_State->get();
	}

	static LuaContext* getCurrentLuaContext() {
		return (LuaContext*)GameScriptEngine::getCurrentScriptExeContext();
	}
private:
	std::shared_ptr<LuaState> m_State;
	std::list<LuaListener*> m_listeners;

	void executeEntryFunction(std::string entryName) {
		lua_getglobal(getState(), entryName.c_str());
		lua_pcall(getState(), 0, 0, 0);
	}

	void doFile(FS::File file) {
		if (luaL_dofile(getState(), file.getFilename().c_str())) {
			//throw ex
			MessageBox(NULL, lua_tostring(getState(), -1), NULL, MB_ICONEXCLAMATION | MB_OK);
		}
	}

	static int Lua_addEventListener(lua_State* L) {
		std::string name = lua_tostring(L, 1);

		getCurrentLuaContext()->addEventListener(
			name,
			luaL_ref(L, LUA_REGISTRYINDEX)
		);
		return 0;
	}

	static int Lua_sleep(lua_State* L) {
		getCurrentLuaContext()->sleep(lua_tointeger(L, 1));
		return 0;
	}

	static int Lua_showWinMessage(lua_State* L) {
		MessageBox(NULL, lua_tostring(L, 1), NULL, MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	static int Lua_addLogMessage(lua_State* L) {
		getCurrentLuaContext()->addConsoleMessage(lua_tostring(L, 1));
		return 0;
	}
};