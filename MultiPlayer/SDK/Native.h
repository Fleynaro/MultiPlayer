#pragma once

#include "Core/ScriptLang/ClassBuilder.h"
#include "Core/ScriptLang/IClassExportable.h"


namespace SDK {
	class Native
	{
	public:
		enum class Type
		{
			Boolean,
			Integer,
			Double,
			String,
			Vector2,
			Vector3,
			Vector4,
			Void
		};

		static Type getTypeByRawType(std::string rawType, bool& isPointer) {
			auto tokens = Generic::String::Split(rawType + " _", " ");

			isPointer = false;
			for (auto it : tokens) {
				if (it == "*") {
					isPointer = true;
					break;
				}
			}

			if (tokens[0] == "bool") {
				return Type::Boolean;
			}
			if (tokens[0] == "int" || tokens[0] == "long" || tokens[1] == "long") {
				return Type::Integer;
			}
			else if (tokens[0] == "float" || tokens[0] == "double") {
				return Type::Double;
			}
			else if (tokens[0] == "char") {
				if (isPointer)
					return Type::String; else return Type::Integer;
			}
			else if (tokens[0] == "class" || tokens[0] == "struct") {
				if (tokens[1] == "SE::Vector2")
					return Type::Vector2;
				if (tokens[1] == "SE::Vector3")
					return Type::Vector3;
				if (tokens[1] == "SE::Vector4")
					return Type::Vector4;
			}

			return Type::Void;
		}

		class Pointer : public Class::IExportable<Pointer>
		{
			friend class Native;
		public:
			//for export
			Pointer* getPersistent() override {
				auto pointer = constructor();
				pointer->m_value = m_value;
				return pointer;
			}

			static Pointer* constructor() {
				return new Pointer;
			}

			Pointer() = default;

			uint64_t getInteger() {
				return *getPtr<uint64_t>();
			}

			bool getBoolean() {
				return *getPtr<bool>();
			}

			double getDouble() {
				return *getPtr<double>();
			}

			std::string getString() {
				return getPtr<char>();
			}
		private:
			uint64_t m_value = 0;

			template<typename T = decltype(m_value)>
			T* getPtr() {
				return (T*)&m_value;
			}
		};

		//Lua
		class Lua
		{
		public:
			static int call(lua_State* L)
			{
				if (!lua_isinteger(L, 1))
					return 0;

				auto native = IGameNativeHelper::getNative(lua_tointeger(L, 1));
				if (native != nullptr)
				{
					auto signature = Class::Member::parseSignature(native->getSignature());
					auto argCount = lua_gettop(L) - 1;
					if (argCount > signature.second.size()) {
						argCount = (int)signature.second.size();
					}

					IGameNative::getContext()->reset();
					for (int i = 0; i < argCount; i++) {
						setArg(L, signature.second[i], i);
					}
						
					native->execute();
					
					return setResult(L, signature.first);
				}
				return 0;
			}

			static void setArg(lua_State* L, std::string rawType, int n, int offset = 2) {
				int idx = n + offset;
				bool isPointer;
				auto type = getTypeByRawType(rawType, isPointer);

				if (isPointer && type != Type::String)
				{
					Pointer* pointer = Class::Adapter::Lua_caller::UnwrapObj(L, idx)->get<Pointer>();
					IGameNative::getContext()->setArg(n, pointer->getPtr());
					return;
				}

				switch (type)
				{
					case Type::Boolean:
					{
						if (lua_isboolean(L, idx)) {
							IGameNative::getContext()->setArg(n, lua_toboolean(L, idx));
							break;
						}
					}
					
					case Type::Integer:
					{
						if (lua_isinteger(L, idx)) {
							IGameNative::getContext()->setArg(n, lua_tointeger(L, idx));
							break;
						}
					}

					case Type::Double:
					{
						if (!lua_isnumber(L, idx))
							return;

						IGameNative::getContext()->setArg(n, lua_tonumber(L, idx));
						break;
					}

					case Type::String:
					{
						if (!lua_isstring(L, idx))
							return;

						IGameNative::getContext()->setArg(n, lua_tostring(L, idx));
						break;
					}
				}
			}

			static int setResult(lua_State* L, std::string rawType) {
				bool isPointer;
				auto type = getTypeByRawType(rawType, isPointer);
				switch (type)
				{
					case Type::Boolean:
					{
						auto val = IGameNative::getContext()->getResult<bool>();
						Class::Adapter::Lua_caller::PushValue(val, L);
						return 1;
					}
					case Type::Integer:
					{
						auto val = IGameNative::getContext()->getResult<uint64_t>();
						Class::Adapter::Lua_caller::PushValue(val, L);
						return 1;
					}
					case Type::Double:
					{
						auto val = IGameNative::getContext()->getResult<float>();
						Class::Adapter::Lua_caller::PushValue(val, L);
						return 1;
					}
					case Type::String:
					{
						auto val = IGameNative::getContext()->getResult<const char*>();
						Class::Adapter::Lua_caller::PushValue(val, L);
						return 1;
					}
					case Type::Vector2:
					{
						auto val = IGameNative::getContext()->getResult<SE::Vector2>();
						Class::Adapter::Lua_caller::PushValue(val.x, L);
						Class::Adapter::Lua_caller::PushValue(val.y, L);
						return 2;
					}
					case Type::Vector3:
					{
						auto val = IGameNative::getContext()->getResult<SE::Vector3>();
						Class::Adapter::Lua_caller::PushValue(val.x, L);
						Class::Adapter::Lua_caller::PushValue(val.y, L);
						Class::Adapter::Lua_caller::PushValue(val.z, L);
						return 3;
					}
				}
				return 0;
			}
		};

		//JavaScript V8
		class V8
		{
		public:
			static void call(const v8::FunctionCallbackInfo<v8::Value>& args)
			{

			}
		};
	};
};