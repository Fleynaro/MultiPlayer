#include "ClassBuilder.h"


using namespace Class;

Builder* Builder::setLuaAccessorFilter(Lua_AccessorFilter get, Lua_AccessorFilter set)
{
	m_lua_get = get;
	m_lua_set = set;
	return this;
}

Builder* Builder::setLuaDestructor(Lua_Delete destructor) {
	m_lua_destructor = destructor;
	return this;
}

Builder* Builder::setParent(Builder* parent) {
	m_parent = parent;
	return this;
}

Builder* Builder::setConstructor(Constructor* method) {
	m_constructor = method;
	return this;
}

Builder* Builder::addMember(Member* member) {
	m_members.push_back(member);
	return this;
}

Builder* Builder::removeMember(Member* member) {
	m_members.remove(member);
	return this;
}

Member* Builder::getMemberByName(std::string name)
{
	std::size_t hash = std::hash<std::string>{}(name);

	auto Class = this;
	do {
		auto it = std::find_if(Class->m_members.begin(), Class->m_members.end(), [hash](const Member* member) {
			return hash == member->getHash();
		});

		if (it != m_members.end())
			return *it;

		Class = Class->getParent();
	} while (Class != nullptr);

	return nullptr;
}

void Builder::V8_RegisterAll(Local<ObjectTemplate>& obj, Isolate* isolate) {
	auto Class = this;
	do {
		for (auto it : Class->m_members) {
			it->V8_Register(obj, isolate);
		}
		Class = Class->getParent();
	} while (Class != nullptr);
}

Local<FunctionTemplate> Builder::V8_MakeTemplate(Isolate * isolate) {
	EscapableHandleScope handle_scope(isolate);

	if (m_constructor == nullptr) {
		//throw ex
	}

	Local<FunctionTemplate> f_obj = FunctionTemplate::New(isolate, m_constructor->V8_getCall());

	auto obj = f_obj->InstanceTemplate();
	obj->SetInternalFieldCount(1);
	V8_RegisterAll(obj, isolate);

	return handle_scope.Escape(f_obj);
}

void Builder::Lua_newMetaTable(lua_State* L)
{
	//table(for global accessing)
	lua_newtable(L);

	if (hasConstructor())
	{
		lua_pushcfunction(L, m_constructor->Lua_getCall()),
			lua_setfield(L, -2, "New");
	}

	for (auto it : m_members) {
		if (it->isStatic())
			it->Lua_Push(L);
	}

	lua_setglobal(L, getName().c_str());

	//meta table(for concrete objects)
	if (hasConstructor())
	{
		luaL_newmetatable(L, getName().c_str());
		lua_pushvalue(L, -1),
			lua_setfield(L, -2, "__index");

		lua_pushcfunction(L, m_lua_get),
			lua_setfield(L, -2, "__index");
		lua_pushcfunction(L, m_lua_set),
			lua_setfield(L, -2, "__newindex");
		lua_pushcfunction(L, m_lua_destructor),
			lua_setfield(L, -2, "__gc");

		auto Class = this;
		do {
			for (auto it : Class->m_members) {
				if (!it->isStatic())
					it->Lua_Push(L);
			}
			Class = Class->getParent();
		} while (Class != nullptr);

		lua_pop(L, 1);
	}
}

std::pair<Builder*, Enum*> Environment::getEnumByRawTypeName(const std::string& rawTypeName) {
	for (auto Class : getClasses()) {
		for (auto member : Class->getMembers()) {
			if (!member->isEnum())
				continue;

			if (rawTypeName == member->getType()) {
				return std::make_pair(Class, (Enum*)member);
			}
		}
	}
	return std::make_pair(nullptr, nullptr);
}
