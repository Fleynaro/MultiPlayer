#pragma once


#include "main.h"
#include "JavaScript/V8_include.h"
#include "Lua/Lua_include.h"
#include "define_link.h"
#include "IClassExportable.h"

#include "Utility/Generic.h"



namespace Class
{
	template<class C>
	struct Info {
		typedef C ClassType;
	public:
		static constexpr bool isDoublePointer() {
			return false;
		}
	};

	template<class C>
	struct Info<C*> {
		typedef C ClassType;
	public:
		static constexpr bool isDoublePointer() {
			return false;
		}
	};

	template<class C>
	struct Info<C**> {
		typedef C ClassType;
	public:
		static constexpr bool isDoublePointer() {
			return true;
		}
	};

	template<class C>
	struct Info<C&> {
		typedef C ClassType;
	public:
		static constexpr bool isDoublePointer() {
			return false;
		}
	};


	namespace Adapter
	{
		class WrappedObj
		{
		public:
			WrappedObj(void* ptr = nullptr)
				: m_ptr(ptr)
			{}
			~WrappedObj() {}

			template<typename T>
			T* get() {
				return (T*)m_ptr;
			}

			template<typename T>
			T** getPtr() {
				return (T**)&m_ptr;
			}

			template<typename T>
			void release() {
				auto ptr = (IExportable<T>*)m_ptr;
				if (ptr->IExportable<T>::decRefCounter()) {
					delete ptr;
				}
				delete this;
			}
		private:
			void* m_ptr;
		};
	};


	using namespace v8;
	
	class Constructor;
	class Enum;
	class Member;


	class Builder
	{
	public:
		Builder(std::string name)
			: m_name(name)
		{}
		~Builder() {}
		
		typedef int(*Lua_AccessorFilter)(lua_State*);
		Builder* setLuaAccessorFilter(Lua_AccessorFilter get, Lua_AccessorFilter set);

		typedef int(*Lua_Delete)(lua_State*);
		Builder* setLuaDestructor(Lua_Delete destructor);

		Builder* setParent(Builder* parent);
		Builder* setConstructor(Constructor* method);
		Builder* addMember(Member* member);
		Builder* removeMember(Member* member);

		Member* getMemberByName(std::string name);

		void V8_RegisterAll(Local<ObjectTemplate>& obj, Isolate* isolate = Isolate::GetCurrent());
		Local<FunctionTemplate> V8_MakeTemplate(Isolate* isolate = Isolate::GetCurrent());

		void Lua_newMetaTable(lua_State* L);

		template<typename T>
		Local<v8::Object> V8_Wrap(T* pObj, Isolate* isolate = Isolate::GetCurrent()) {
			static Global<ObjectTemplate> V8_tpl;

			EscapableHandleScope handle_scope(isolate);

			if (V8_tpl.IsEmpty()) {
				Local<FunctionTemplate> raw_template = V8_MakeTemplate(isolate);
				V8_tpl.Reset(isolate, raw_template->InstanceTemplate());
			}

			Local<ObjectTemplate> templ =
				Local<ObjectTemplate>::New(isolate, V8_tpl);
			Local<Object> obj =
				templ->NewInstance(isolate->GetCurrentContext()).ToLocalChecked();

			Local<External> obj_ptr = External::New(isolate, pObj);
			obj->SetInternalField(0, obj_ptr);
			//makeweak
			
			return handle_scope.Escape(obj);
		}

		template<class T>
		void Lua_new(T* pObj, lua_State* L) {
			*reinterpret_cast<Adapter::WrappedObj**>(
				lua_newuserdata(L, sizeof(Adapter::WrappedObj*))
			) = new Adapter::WrappedObj(pObj);
			luaL_setmetatable(L, getName().c_str());
			pObj->IExportable<T>::incRefCounter();
		}

		bool hasConstructor() {
			return m_constructor != nullptr;
		}

		Builder* getParent() const {
			return m_parent;
		}

		std::string getName() const {
			return m_name;
		}

		std::string getRawName() const {
			return m_rawName;
		}

		void setRawName(std::string rawName) {
			m_rawName = rawName;
		}

		Constructor* getConstructor() {
			return m_constructor;
		}

		std::list<Member*>& getMembers() {
			return m_members;
		}
	private:
		std::string m_name;
		std::string m_rawName;
		Builder* m_parent = nullptr;
		Constructor* m_constructor = nullptr;
		std::list<Member*> m_members;

		Lua_AccessorFilter m_lua_get = nullptr;
		Lua_AccessorFilter m_lua_set = nullptr;
		Lua_Delete m_lua_destructor = nullptr;
	};


	class Environment
	{
	public:
		template<typename C>
		static void addClass(Builder* Class) {
			CLASS_EXPORTABLE_ASSERT(C);

			getClasses().push_back(Class);
			IExportable<C>::setClassBuilder(Class);
			Class->setRawName(
				Generic::String::Split(typeid(C).name(), " ")[1]
			);
		}
		
		static void addStaticClass(Builder* Class) {
			getClasses().push_back(Class);
		}

		template<typename C>
		static void removeClass(Builder* Class) {
			CLASS_EXPORTABLE_ASSERT(C);

			getClasses().remove(Class);
			IExportable<C>::setClassBuilder(nullptr);
		}

		static std::list<Builder*>& getClasses() {
			return m_classes;
		}

		static Builder* getClassBuilderByRawName(const std::string& rawName) {
			for (auto Class : getClasses()) {
				if (rawName == Class->getRawName()) {
					return Class;
				}
			}
			return nullptr;
		}

		static std::pair<Builder*, Enum*> getEnumByRawTypeName(const std::string& rawTypeName);
	private:
		inline static std::list<Builder*> m_classes;
	};


	namespace Adapter
	{
		template <typename ArgSet, uint32_t index, uint32_t ArgCount>
		inline static void ConvertTupleToStringArray(std::vector<std::string>& array)
		{
			using Arg = std::tuple_element<index, ArgSet>;
			array[index] = typeid(Arg::type).name();
			//continue if any next args exist
			if constexpr (index + 1 < ArgCount)
			{
				ConvertTupleToStringArray<ArgSet, index + 1, ArgCount>(array);
			}
		}

		namespace V8_Caller
		{
			template <typename T>
			inline static T* UnwrapObj(Local<v8::Object> obj)
			{
				Local<External> field = Local<External>::Cast(obj->GetInternalField(0));
				void* ptr = field->Value();
				return static_cast<T*>(ptr);
			}

			template <uint32_t index, typename ArgSet>
			inline static void SetArg(ArgSet& Args_, Local<Value> value, Isolate* isolate)
			{
				using Arg = std::tuple_element<index, ArgSet>;

				//possible argument types: int(uint32_t, uint64_t) | float | double | std::string(const char*) | Class | Class*

				//transform the input args
				if constexpr (std::is_same<Arg::type, int>::value)
				{
					if (!value->IsInt32()) {
						//throw ex
					}
					auto val = value->ToInt32(isolate);
					std::get<index>(Args_) = val->Value();
				}
				else if constexpr (std::is_same<Arg::type, bool>::value)
				{
					if (!value->IsBoolean()) {
						//throw ex
					}
					auto val = value->ToBoolean(isolate);
					std::get<index>(Args_) = val->Value();
				}
				else if constexpr (std::is_same<Arg::type, float>::value || std::is_same<Arg::type, double>::value)
				{
					if (!value->IsNumber()) {
						//throw ex
					}
					auto val = value->ToNumber(isolate);
					std::get<index>(Args_) = (typename Arg::type)val->Value();
				}
				else if constexpr (std::is_same<Arg::type, std::string>::value || std::is_same<Arg::type, const char*>::value)
				{
					if (!value->IsString()) {
						//throw ex
					}
					String::Utf8Value utf8(isolate, value);
					std::get<index>(Args_) = *utf8;
				}
				else if constexpr (std::is_pointer<Arg::type>::value)
				{
					if (!value->IsObject()) {
						//throw ex
					}
					reinterpret_cast<void*&>(std::get<index>(Args_)) = UnwrapObj<void*>(value->ToObject(isolate));
				}
				else if constexpr (std::is_class<Arg::type>::value)
				{
					if (!value->IsObject()) {
						//throw ex
					}
					reinterpret_cast<typename Arg::type&>(std::get<index>(Args_)) = *(typename Arg::type*)UnwrapObj<void*>(value->ToObject(isolate));
				}
			}

			template <typename ArgSet, uint32_t index, uint32_t ArgCount>
			inline static void ConvertArgArrayToTupleTpl(const FunctionCallbackInfo<Value>& v8_args, ArgSet& Args_)
			{
				SetArg<index>(Args_, v8_args[index], v8_args.GetIsolate());

				//continue if any next args exist
				if constexpr (index + 1 < ArgCount)
				{
					ConvertArgArrayToTupleTpl<ArgSet, index + 1, ArgCount>(v8_args, Args_);
				}
			}

			template <typename ArgSet, uint32_t ArgCount>
			inline static void ConvertArgArrayToTuple(const FunctionCallbackInfo<Value>& v8_args, ArgSet& Args_)
			{
				ConvertArgArrayToTupleTpl<ArgSet, 0, ArgCount>(v8_args, Args_);
			}

			template <typename R>
			inline static Local<Value> getLocalValue(R &value, Isolate* isolate)
			{
				//possible return types: int(uint32_t, uint64_t) | float | double | std::string(const char*) | Class | Class* | Class&

				Local<Value> result;
				if constexpr (std::is_same<R, int>::value) {
					result = Local<Integer>::New(
						isolate,
						Integer::New(isolate, value)
					);
				}
				else if constexpr (std::is_same<R, bool>::value) {
					result = Local<Boolean>::New(
						isolate,
						Boolean::New(isolate, value)
					);
				}
				else if constexpr (std::is_same<R, float>::value || std::is_same<R, double>::value) {
					result = Local<Number>::New(
						isolate,
						Number::New(isolate, (double)value)
					);
				}
				else if constexpr (std::is_same<R, const char*>::value)
				{
					result = String::NewFromUtf8(isolate, value, NewStringType::kNormal).ToLocalChecked();
				}
				else if constexpr (std::is_same<R, std::string>::value)
				{
					result = String::NewFromUtf8(isolate, value.c_str(), NewStringType::kNormal).ToLocalChecked();
				}
				else if constexpr (std::is_pointer<R>::value || std::is_class<R>::value)
				{
					using classType = typename Class::Info<R>::ClassType;
					CLASS_EXPORTABLE_ASSERT(classType);

					auto Class = IExportable<classType>::getClassBuilder();
					if (Class == nullptr) {
						//throw ex
					}

					if constexpr (std::is_pointer<R>::value) {
						value->IExportable<classType>::toDynamic();
						result = Class->V8_Wrap(value, isolate);
					}
					else {
						if (value.IExportable<classType>::isDynamic()) {
							result = Class->V8_Wrap(&value, isolate);
						}
						else {
							auto ptr = value.classType::getPersistent();
							ptr->IExportable<classType>::toDynamic();
							result = Class->V8_Wrap(ptr, isolate);
						}
					}
				}
				else {
					result = Undefined(isolate);
				}

				return result;
			}

			template <typename R>
			inline static void setReturnedValue(ReturnValue<Value> returnValue, R value, Isolate* isolate)
			{
				//Return the value
				returnValue.Set(
					getLocalValue(value, isolate)
				);
			}
		};

		namespace Lua_caller
		{
			inline static WrappedObj* UnwrapObj(lua_State* L, int lua_Index = 0)
			{
				auto userDataPtr = lua_touserdata(L, lua_Index);
				if (userDataPtr != NULL) {
					return *reinterpret_cast<WrappedObj **>(userDataPtr);
				}
				else {
					auto newObj = new WrappedObj;
					//lua_rawsetp(L, -1, newObj);
					return newObj;
				}
			}

			template <uint32_t index, typename ArgSet>
			inline static void PopValue(ArgSet& Args_, int lua_Index, lua_State* L)
			{
				using Arg = std::tuple_element<index, ArgSet>;

				//transform the input args
				if constexpr (std::is_same<Arg::type, bool>::value)
				{
					std::get<index>(Args_) = lua_toboolean(L, lua_Index);
				}
				else if constexpr (std::is_same<Arg::type, float>::value || std::is_same<Arg::type, double>::value)
				{
					std::get<index>(Args_) = (typename Arg::type)luaL_checknumber(L, lua_Index);
				}
				else if constexpr (std::is_same<Arg::type, std::string>::value || std::is_same<Arg::type, const char*>::value)
				{
					std::get<index>(Args_) = lua_tostring(L, lua_Index);
				}
				else if constexpr (std::is_integral<Arg::type>::value || std::is_enum<Arg::type>::value)
				{
					std::get<index>(Args_) = (typename Arg::type)lua_tointeger(L, lua_Index);
				}
				else if constexpr (std::is_pointer<Arg::type>::value)
				{
					auto obj = UnwrapObj(L, lua_Index)->getPtr<void*>();
					if constexpr (Class::Info<Arg::type>::isDoublePointer())
					{
						reinterpret_cast<void*&>(std::get<index>(Args_)) = obj;
					}
					else {
						reinterpret_cast<void*&>(std::get<index>(Args_)) = *obj;
					}
				}
				else if constexpr (std::is_class<Arg::type>::value)
				{
					reinterpret_cast<typename Arg::type&>(std::get<index>(Args_)) = *UnwrapObj(L, lua_Index)->get<typename Arg::type>();
				}
			}

			template <typename R>
			inline static int PushValue(R &value, lua_State* L)
			{
				//possible return types: int(uint32_t, uint64_t) | float | double | std::string(const char*) | Class | Class* | Class&
				
				if constexpr (std::is_same<R, bool>::value) {
					lua_pushboolean(L, value);
				}
				else if constexpr (std::is_same<R, float>::value || std::is_same<R, double>::value) {
					lua_pushnumber(L, (double)value);
				}
				else if constexpr (std::is_same<R, const char*>::value)
				{
					lua_pushstring(L, value);
				}
				else if constexpr (std::is_integral<R>::value || std::is_enum<R>::value) {
					lua_pushinteger(L, (uint64_t)value);
				}
				else if constexpr (std::is_same<R, std::string>::value)
				{
					lua_pushstring(L, value.c_str());
				}
				else if constexpr (std::is_pointer<R>::value || std::is_class<R>::value)
				{
					using classType = typename Class::Info<R>::ClassType;
					CLASS_EXPORTABLE_ASSERT(classType);

					auto Class = IExportable<classType>::getClassBuilder();
					if (Class == nullptr) {
						//throw ex
					}

					if constexpr (std::is_pointer<R>::value) {
						value->IExportable<classType>::toDynamic();
						Class->Lua_new(value, L);
					}
					else {
						if (value.IExportable<classType>::isDynamic()) {
							Class->Lua_new(&value, L);
						}
						else {
							auto ptr = value.classType::getPersistent();
							ptr->IExportable<classType>::toDynamic();
							Class->Lua_new(ptr, L);
						}
					}
				}
				else {
					lua_pushnil(L);
				}

				return 1;
			}

			template <typename ArgSet, uint32_t index, uint32_t ArgCount>
			inline static void ConvertArgStackToTupleTpl(lua_State* L, ArgSet& Args_, int offset)
			{
				PopValue<index>(Args_, index + offset, L);

				//continue if any next args exist
				if constexpr (index + 1 < ArgCount)
				{
					ConvertArgStackToTupleTpl<ArgSet, index + 1, ArgCount>(L, Args_, offset);
				}
			}

			template <typename ArgSet, uint32_t ArgCount>
			inline static void ConvertArgStackToTuple(lua_State* L, ArgSet& Args_, int offset = 1)
			{
				ConvertArgStackToTupleTpl<ArgSet, 0, ArgCount>(L, Args_, offset);
			}
		};

		template <typename T, uint32_t ID> class StaticMethod;
		template<typename R, typename... Args, uint32_t ID>
		class StaticMethod<R(Args ...), ID>
		{
			typedef R(*FT)(Args ...);
		public:
			using ArgSet = std::tuple<Args...>;
			template <std::size_t N>
			using ArgType = typename std::tuple_element<N, ArgSet>::type;
			static const int ArgCount = std::tuple_size<ArgSet>::value;

			//pointer to a class orig method
			inline static FT m_method = nullptr;

			//JavaScript V8
			class V8
			{
			public:
				static void call(const FunctionCallbackInfo<Value>& args)
				{

				}

				static void constructor(const FunctionCallbackInfo<Value>& args)
				{
					using classType = typename Class::Info<R>::ClassType;
					CLASS_EXPORTABLE_ASSERT(classType);

					//transform the arguments
					ArgSet Args_;
					if constexpr (ArgCount > 0) {
						V8_Caller::ConvertArgArrayToTuple<ArgSet, ArgCount>(args, Args_);
					}
					R obj_ptr = std::apply(m_method, Args_);
					obj_ptr->IExportable<classType>::toDynamic();

					args.This()->SetInternalField(0,
						External::New(args.GetIsolate(), obj_ptr)
					);
					args.GetReturnValue().Set(args.This());
				}
			};

			//Lua
			class Lua
			{
			public:
				static int call(lua_State* L)
				{
					//transform the arguments
					ArgSet Args_;
					if constexpr (ArgCount > 0) {
						Lua_caller::ConvertArgStackToTuple<ArgSet, ArgCount>(L, Args_);
					}

					if constexpr (!std::is_same<R, void>::value) {
						//execute the static method
						R ret_value = std::apply(m_method, Args_);

						//Return the value
						Lua_caller::PushValue(ret_value, L);
						return 1;
					}
					else {
						//execute the method without the result value
						std::apply(m_method, Args_);
						return 0;
					}
					return 1;
				}

				static int constructor(lua_State* L)
				{
					using classType = typename Class::Info<R>::ClassType;
					CLASS_EXPORTABLE_ASSERT(classType);

					//transform the arguments
					ArgSet Args_;
					if constexpr (ArgCount > 0) {
						Lua_caller::ConvertArgStackToTuple<ArgSet, ArgCount>(L, Args_);
					}

					R obj_ptr = std::apply(m_method, Args_);
					Lua_caller::PushValue(obj_ptr, L);
					return 1;
				}
			};
		};

		template<typename R, typename... Args, uint32_t ID>
		class StaticMethod<R(*)(Args ...), ID>
			: public StaticMethod<R(Args ...), ID> {};

		template <typename T, uint32_t ID> class Method;
		template<typename T, typename R, typename... Args, uint32_t ID>
		class Method<R(T::*)(Args ...), ID>
		{
			typedef R(T::* FT)(Args ...);
		public:
			using ArgSet = std::tuple<Args...>;
			static const int ArgCount = std::tuple_size<ArgSet>::value;

			//pointer to a class orig method
			inline static FT m_method = nullptr;


			//JavaScript V8
			class V8
			{
			public:
				static void call(const FunctionCallbackInfo<Value>& args)
				{
					//getting the pointer
					T* obj = V8_Caller::UnwrapObj<T>(args.This());

					//transform the arguments
					ArgSet Args_;
					if constexpr (ArgCount > 0) {
						V8_Caller::ConvertArgArrayToTuple<ArgSet, ArgCount>(args, Args_);
					}

					if constexpr (!std::is_same<R, void>::value) {
						//execute the method
						R ret_value = std::apply(m_method, std::tuple_cat(std::make_tuple(obj), Args_));

						//Return the value
						V8_Caller::setReturnedValue(args.GetReturnValue(), ret_value, args.GetIsolate());
					}
					else {
						//execute the method without the result value
						std::apply(m_method, std::tuple_cat(std::make_tuple(obj), Args_));
					}
				}

				static void call_accessor_get(Local<String> property, const PropertyCallbackInfo<Value>& info)
				{
					static_assert(ArgCount == 0);

					//getting the pointer
					T * obj = V8_Caller::UnwrapObj<T>(info.This());

					//execute the method
					R ret_value = std::apply(m_method, std::make_tuple(obj));

					//Return the value
					V8_Caller::setReturnedValue(info.GetReturnValue(), ret_value, info.GetIsolate());
				}

				static void call_accessor_set(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info)
				{
					static_assert(ArgCount == 1);

					//getting the pointer
					T * obj = V8_Caller::UnwrapObj<T>(info.This());

					//transform the arguments
					ArgSet Args_;
					V8_Caller::SetArg<0>(Args_, value, info.GetIsolate());

					//execute the method
					std::apply(m_method, std::tuple_cat(std::make_tuple(obj), Args_));
				}
			};
			
			//Lua
			class Lua
			{
			public:
				static int call(lua_State* L)
				{
					//getting the pointer
					T* obj = Lua_caller::UnwrapObj(L, 1)->get<T>();

					//transform the arguments
					ArgSet Args_;
					if constexpr (ArgCount > 0) {
						Lua_caller::ConvertArgStackToTuple<ArgSet, ArgCount>(L, Args_, 2);
					}

					if constexpr (!std::is_same<R, void>::value) {
						//execute the method
						R ret_value = std::apply(m_method, std::tuple_cat(std::make_tuple(obj), Args_));

						//Return the value
						Lua_caller::PushValue(ret_value, L);
						return 1;
					}
					else {
						//execute the method without the result value
						std::apply(m_method, std::tuple_cat(std::make_tuple(obj), Args_));
						return 0;
					}
				}

				static int call_accessor_get(lua_State* L)
				{
					static_assert(ArgCount == 0);

					//getting the pointer
					T* obj = Lua_caller::UnwrapObj(L, 1)->get<T>();
					
					//execute the method
					R ret_value = std::apply(m_method, std::make_tuple(obj));

					//Return the value
					Lua_caller::PushValue(ret_value, L);
					return 1;
				}

				static int call_accessor_set(lua_State* L)
				{
					static_assert(ArgCount == 1);

					//getting the pointer
					T* obj = Lua_caller::UnwrapObj(L, 1)->get<T>();

					//transform the arguments
					ArgSet Args_;
					Lua_caller::PopValue<0>(Args_, 3, L);

					//execute the method
					std::apply(m_method, std::tuple_cat(std::make_tuple(obj), Args_));
					return 0;
				}
			};
		};


		class ICallback
		{
		public:
			virtual void V8_getParams(std::vector<v8::Local<v8::Value>>& args, Isolate* isolate) = 0;
			virtual void Lua_pushParams(lua_State* L, int &length) = 0;
		};

		template<typename... Params>
		class Callback : public ICallback
		{
		public:
			using ArgSet = std::tuple<Params...>;
			static const int ArgCount = std::tuple_size<ArgSet>::value;

			Callback(ArgSet params) {
				m_params = params;
			}

			void V8_getParams(std::vector<v8::Local<v8::Value>>& params, Isolate* isolate) override {
				if (ArgCount == 0)
					return;
				V8::getParams<0>(m_params, params, isolate);
			}

			void Lua_pushParams(lua_State* L, int& length) override {
				if (ArgCount == 0)
					return;
				Lua::pushParams<0>(m_params, L);
				length = ArgCount;
			}
		private:
			ArgSet m_params;

			class V8
			{
			public:

				template <uint32_t index>
				inline static void getParams(ArgSet &params_, std::vector<v8::Local<v8::Value>> &params_arr, Isolate* isolate)
				{
					params_arr.push_back(
						V8_Caller::getLocalValue(
							std::get<index>(params_),
							isolate
						)
					);
					if constexpr (index + 1 < ArgCount)
					{
						getParams<index + 1>(params_, params_arr, isolate);
					}
				}
			};

			class Lua
			{
			public:
				template <uint32_t index>
				inline static void pushParams(ArgSet& params_, lua_State* L)
				{
					Lua_caller::PushValue(std::get<index>(params_), L);

					if constexpr (index + 1 < ArgCount)
					{
						pushParams<index + 1>(params_, L);
					}
				}
			};
		};
	};


	class Member
	{
	public:
		Member(std::string name) : m_name(name) {
			m_hash = std::hash<std::string>{}(name);
		}
		~Member() {}

		enum class Access {
			Public,
			Private,
			Protected
		};

		Member* setPublic() {
			setAccess(Access::Public);
			return this;
		}

		Member* setPrivate() {
			setAccess(Access::Private);
			return this;
		}

		Member* setProtected() {
			setAccess(Access::Protected);
			return this;
		}

		Member* setAccess(Access type) {
			m_access = type;
			return this;
		}

		std::string& getName() {
			return m_name;
		}

		std::size_t getHash() const {
			return m_hash;
		}

		virtual bool isAccessor() = 0;
		virtual bool isStatic() = 0;
		virtual bool isEnum() = 0;
		virtual bool isMethod() {
			return !isAccessor() && !isStatic() && !isEnum();
		}
		virtual bool isStaticMethod() {
			return isStatic() && !isEnum();
		}

		virtual void V8_Register(Local<ObjectTemplate>& obj, Isolate* isolate = Isolate::GetCurrent()) = 0;
		virtual void Lua_Push(lua_State* L, int offset = -2) = 0;
		//...

		std::string& getType() {
			return m_type;
		}

		static auto parseSignature(const std::string& signature) {
			using namespace Generic::String;
			std::pair<std::string, std::vector<std::string>> result;

			auto tokens = Split(signature + "_", "[)(]");

			auto& argList = *(tokens.end() - 2);
			replaceSymbolWithin(argList, "<>", ',', ' ');
			auto args = Split(argList, ",");

			result.first = tokens[0];
			if (!(args.size() == 1 && args[0] == "void")) {
				for (auto it : args) {
					result.second.push_back(it);
				}
			}

			return result;
		}
	protected:
		std::string m_type;
	private:
		std::string m_name;
		std::size_t m_hash;
		Access m_access = Access::Public;
	};


	class Enum : public Member
	{
	public:
		Enum(std::string name)
			: Member(name)
		{}

		template<typename T>
		Enum* setLink() {
			auto tokens = Generic::String::Split(typeid(T).name(), " ");
			if (tokens[0] != "enum") {
				assert(1);
			}
			m_type = tokens[1];
			return this;
		}

		Enum* addItem(const std::string& name, uint64_t value) {
			m_items[name] = value;
			return this;
		}

		Enum* addItems(const json& data) {
			if (data.is_null()) {
				return this;
			}

			uint64_t counter = 0;
			for (auto const& it : data) {
				if (it.is_string()) {
					addItem(it.get<std::string>(), counter++);
				}
				else if (it.is_array()) {
					counter = it[1].get<uint64_t>();
					addItem(it[0].get<std::string>(), counter++);
				}
			}
			return this;
		}

		uint64_t get(std::string name) {
			return m_items[name];
		}

		bool isAccessor() override {
			return false;
		}

		bool isStatic() override {
			return true;
		}

		bool isEnum() override {
			return true;
		}

		void V8_Register(Local<ObjectTemplate>& obj, Isolate* isolate = Isolate::GetCurrent()) override {}
		void Lua_Push(lua_State* L, int offset = -2) override {
			lua_newtable(L);

			for (auto const& it : getItems()) {
				lua_pushinteger(L, it.second),
					lua_setfield(L, -2, it.first.c_str());
			}

			lua_setfield(L, -2, getName().c_str());
		}

		std::unordered_map<std::string, uint64_t>& getItems() {
			return m_items;
		}
	private:
		std::unordered_map<std::string, uint64_t> m_items;
	};


	class Accessor : public Member
	{
	public:
		typedef void(*V8_Call_accessor_get)(Local<String>, const PropertyCallbackInfo<Value>&);
		typedef void(*V8_Call_accessor_set)(Local<String>, Local<Value>, const PropertyCallbackInfo<void>&);
		typedef int(*Lua_Call_accessor)(lua_State*);
		
		Accessor(std::string name)
			: Member(name)
		{}
		~Accessor() {}

		template<uint32_t MethodId, typename T>
		Accessor* setLinkToGET(T fn) {
			using accessorMethod = Adapter::Method<T, MethodId>;
			accessorMethod::m_method = fn;

			if (m_type.empty()) {
				auto signature = parseSignature(typeid(T).name());
				m_type = signature.first;
			}

			//for v8
			m_v8_call_accessor_get = accessorMethod::V8::call_accessor_get;
			//for lua
			m_lua_call_accessor_get = accessorMethod::Lua::call_accessor_get;
			//...
			return this;
		}

		template<uint32_t MethodId, typename T>
		Accessor* setLinkToSET(T fn) {
			using accessorMethod = Adapter::Method<T, MethodId>;
			accessorMethod::m_method = fn;

			if (m_type.empty()) {
				auto signature = parseSignature(typeid(T).name());
				m_type = signature.second[0];
			}

			//for v8
			m_v8_call_accessor_set = accessorMethod::V8::call_accessor_set;
			//for lua
			m_lua_call_accessor_set = accessorMethod::Lua::call_accessor_set;
			//...
			return this;
		}

		bool isAccessor() override {
			return true;
		}

		bool isStatic() override {
			return false;
		}

		bool isEnum() override {
			return false;
		}

		void V8_Register(Local<ObjectTemplate>& obj, Isolate* isolate = Isolate::GetCurrent()) override {
			obj->SetAccessor(
				String::NewFromUtf8(
					isolate,
					getName().c_str(),
					v8::NewStringType::kNormal
				).ToLocalChecked(),
				m_v8_call_accessor_get, m_v8_call_accessor_set
			);
		}

		void Lua_Push(lua_State* L, int offset = -2) override {

		}

		Lua_Call_accessor m_lua_call_accessor_get = nullptr;
		Lua_Call_accessor m_lua_call_accessor_set = nullptr;
	private:
		V8_Call_accessor_get m_v8_call_accessor_get = nullptr;
		V8_Call_accessor_set m_v8_call_accessor_set = nullptr;
	};




	template<typename T>
	class Filter
	{
	public:
		static int lua_getter(lua_State* L) {
			Builder* Class = IExportable<T>::getClassBuilder();
			if (Class == nullptr) {
				//throw ex
				return 1;
			}

			auto member = Class->getMemberByName(lua_tostring(L, 2));
			if (member != nullptr && member->isAccessor()) {
				auto accessor = (Accessor*)member;
				if (accessor->m_lua_call_accessor_get != nullptr) {
					return accessor->m_lua_call_accessor_get(L);
				}
			}
			//throw ex
			
			luaL_checkudata(L, 1, Class->getName().c_str());
			lua_rawget(L, 0);
			return 1;
		}

		static int lua_setter(lua_State* L) {
			Builder* Class = IExportable<T>::getClassBuilder();
			if (Class == nullptr) {
				//throw ex
			}
			
			auto member = Class->getMemberByName(lua_tostring(L, 2));
			if (member != nullptr && member->isAccessor()) {
				auto accessor = (Accessor*)member;
				if (accessor->m_lua_call_accessor_set != nullptr) {
					accessor->m_lua_call_accessor_set(L);
					return 0;
				}
			}
			//throw ex

			lua_rawset(L, 0);
			return 0;
		}

		static int lua_delete(lua_State* L) {
			Adapter::Lua_caller::UnwrapObj(L, 1)->release<T>();
			return 0;
		}
	};



	class Method : public Member
	{
	public:
		Method(std::string name)
			: Member(name)
		{}
		~Method() {}

		template<uint32_t MethodId, typename T>
		Method* setLink(T fn) {
			using method = Adapter::Method<T, MethodId>;
			method::m_method = fn;
			setId(MethodId);
			
			parseMethodSignature(typeid(T).name());

			//for v8
			V8_setCall(method::V8::call);
			//for lua
			Lua_setCall(method::Lua::call);
			//...
			return this;
		}

		static constexpr uint64_t anyValue = -10000;
		struct argInfo {
			std::string m_name;
			std::string m_typeName;
			uint64_t m_defaultValue = anyValue;
			argInfo(std::string typeName = "")
				: m_typeName(typeName)
			{}
		};
	protected:
		std::vector<argInfo> m_argInfo;

		template <uint32_t index, typename ArgSet>
		static void SetDefaultArgumentValues(const ArgSet& args, std::vector<argInfo>& argInfo)
		{
			using Arg = std::tuple_element<index, ArgSet>;
			reinterpret_cast<typename Arg::type&>(
				argInfo[index].m_defaultValue
			) = std::get<index>(args);
			
			//continue if any next args exist
			if constexpr (index + 1 < std::tuple_size<ArgSet>::value)
			{
				SetDefaultArgumentValues<index + 1>(args, argInfo);
			}
		}
		
		void parseMethodSignature(const std::string& signatureStr) {
			auto signature = parseSignature(signatureStr);
			
			m_type = signature.first;
			for (auto it : signature.second) {
				m_argInfo.push_back(it);
			}
		}
	public:
		template<typename... Args>
		Method* setDefArgValues(const std::tuple<Args...>& args) {
			SetDefaultArgumentValues<0>(args, m_argInfo);
			return this;
		}

		Method* setArgNames(const std::vector<std::string>& argNames) {
			if (argNames.size() > m_argInfo.size()) {
				m_argInfo.resize(argNames.size());
			}
			
			int i = 0;
			for (auto const& it : argNames) {
				m_argInfo[i ++].m_name = it;
			}
			return this;
		}

		void V8_Register(Local<ObjectTemplate>& obj, Isolate* isolate = Isolate::GetCurrent()) override {
			obj->Set(
				String::NewFromUtf8(
					isolate,
					getName().c_str(),
					v8::NewStringType::kNormal
				).ToLocalChecked(),
				FunctionTemplate::New(
					isolate,
					m_v8_call
				)
			);
		}

		bool isAccessor() override {
			return false;
		}

		bool isStatic() override {
			return false;
		}

		bool isEnum() override {
			return false;
		}

		void Lua_Push(lua_State* L, int offset = -2) override {
			lua_pushcfunction(L, m_lua_call),
				lua_setfield(L, offset, getName().c_str());
		}

		typedef void(*V8_Call)(const FunctionCallbackInfo<Value>&);
		V8_Call V8_getCall() {
			return m_v8_call;
		}

		Method* V8_setCall(V8_Call call) {
			m_v8_call = call;
			return this;
		}

		typedef int(*Lua_Call)(lua_State*);
		Lua_Call Lua_getCall() {
			return m_lua_call;
		}

		Method* Lua_setCall(Lua_Call call) {
			m_lua_call = call;
			return this;
		}

		auto& getArgInfo() {
			return m_argInfo;
		}
	protected:
		uint32_t m_id = 0;
		V8_Call m_v8_call = nullptr;
		Lua_Call m_lua_call = nullptr;

		void setId(uint32_t id) {
			m_id = id;
		}
	};



	class StaticMethod : public Method
	{
	public:
		StaticMethod(std::string name)
			: Method(name)
		{}
		~StaticMethod() {}

		template<typename... Args>
		StaticMethod* setDefArgValues(const std::tuple<Args...>& args) {
			Method::setDefArgValues(args);
			return this;
		}

		StaticMethod* setArgNames(const std::vector<std::string>& argNames) {
			Method::setArgNames(argNames);
			return this;
		}

		template<uint32_t MethodId, typename T>
		StaticMethod* setLink(T fn) {
			using stMethod = Adapter::StaticMethod<T, MethodId>;
			stMethod::m_method = fn;
			setId(MethodId);
			
			parseMethodSignature(typeid(T).name());

			//for v8
			V8_setCall(stMethod::V8::call);
			//for lua
			Lua_setCall(stMethod::Lua::call);
			//...
			return this;
		}

		void V8_Register(Local<ObjectTemplate>& obj, Isolate* isolate = Isolate::GetCurrent()) override {
			
		}

		bool isStatic() override {
			return true;
		}
	};



	class Constructor : public Method
	{
	public:
		Constructor()
			: Method("constructor")
		{}

		template<typename... Args>
		Constructor* setDefArgValues(const std::tuple<Args...>& args) {
			Method::setDefArgValues(args);
			return this;
		}

		Constructor* setArgNames(const std::vector<std::string>& argNames) {
			Method::setArgNames(argNames);
			return this;
		}

		template<uint32_t MethodId, typename T>
		Constructor* setLink(T fn) {
			using constructor = Adapter::StaticMethod<T, MethodId>;
			constructor::m_method = fn;
			setId(MethodId);
			
			parseMethodSignature(typeid(T).name());

			//for v8
			V8_setCall(constructor::V8::constructor);
			//for lua
			Lua_setCall(constructor::Lua::constructor);
			//...
			return this;
		}
	};
};
