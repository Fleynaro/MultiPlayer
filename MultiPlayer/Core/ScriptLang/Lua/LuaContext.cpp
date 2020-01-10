#include "LuaContext.h"


void LuaState::registerObjects() {
	for (auto it : Class::Environment::getClasses()) {
		it->Lua_newMetaTable(get());
	}

	lua_newtable(get());
	lua_pushcfunction(get(), LuaContext::Lua_addEventListener),
		lua_setfield(get(), -2, "addListener");
	lua_setglobal(get(), "Event");

	lua_pushcfunction(get(), LuaContext::Lua_showWinMessage);
	lua_setglobal(get(), "printw");

	lua_pushcfunction(get(), LuaContext::Lua_addLogMessage);
	lua_setglobal(get(), "print");

	lua_pushcfunction(get(), LuaContext::Lua_sleep);
	lua_setglobal(get(), "sleep");
}

int LuaState::setLuaPath(std::string path) {
	auto L = get();
	lua_getglobal(L, "package");
	lua_getfield(L, -1, "path");
	std::string cur_path = lua_tostring(L, -1);
	cur_path.append(";");
	cur_path.append(path);
	lua_pop(L, 1);
	lua_pushstring(L, cur_path.c_str());
	lua_setfield(L, -2, "path");
	lua_pop(L, 1);
	return 0;
}
