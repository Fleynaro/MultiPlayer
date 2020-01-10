#pragma once


#include "main.h"
#include "MinHook.h"


namespace Memory
{

	typedef std::size_t Offset;



	/*
		Work with pointers, not concrete values!
	*/
	class Handle
	{
	protected:
		void* _handle;

	public:
		Handle()
			: _handle(nullptr)
		{ }

		Handle(std::nullptr_t null)
			: _handle(null)
		{ }

		Handle(void* p)
			: _handle(p)
		{ }

		template <typename T>
		Handle(T* p)
			: _handle(const_cast<typename std::remove_cv<T>::type*>(p))
		{ }

		Handle(const std::uintptr_t p)
			: _handle(reinterpret_cast<void*>(p))
		{ }

		Handle(const Handle& copy) = default;

		//interpret the void pointer as the next pointer type
		template <typename T>
		T as() const
		{
			if constexpr (std::is_pointer<T>::value)
				return reinterpret_cast<T>(this->_handle);
			else if constexpr (std::is_lvalue_reference<T>::value)
				return *this->as<typename std::remove_reference<T>::type*>();
			else if constexpr (std::is_array<T>::value)
				return this->as<T&>();
			else if constexpr (std::is_same<T, std::uintptr_t>::value)
				return reinterpret_cast<std::uintptr_t>(this->as<void*>());
			else if constexpr (std::is_same<T, std::intptr_t>::value)
				return reinterpret_cast<std::intptr_t>(this->as<void*>());
			else
				return reinterpret_cast<T>(this->as<void*>());
		}

		bool operator==(const Handle& rhs) const
		{
			return this->as<void*>() == rhs.as<void*>();
		}

		bool operator!=(const Handle& rhs) const
		{
			return this->as<void*>() != rhs.as<void*>();
		}

		bool operator>(const Handle& rhs) const
		{
			return this->as<void*>() > rhs.as<void*>();
		}

		bool operator<(const Handle& rhs) const
		{
			return this->as<void*>() < rhs.as<void*>();
		}

		bool operator>=(const Handle& rhs) const
		{
			return this->as<void*>() >= rhs.as<void*>();
		}

		bool operator<=(const Handle& rhs) const
		{
			return this->as<void*>() <= rhs.as<void*>();
		}

		operator void* () const
		{
			return this->as<void*>();
		}

		bool isValid() const
		{
			return (void*)*this != nullptr;
		}

		//get value that the pointer contains
		template <typename T>
		T get() const
		{
			return *this->as<T*>();
		}

		//add bytes to the current pointer address
		template <typename T>
		typename std::enable_if<std::is_integral<T>::value, Handle>::type add(const T offset) const
		{
			return this->as<std::uintptr_t>() + offset;
		}

		//sub bytes from the current pointer address
		template <typename T>
		typename std::enable_if<std::is_integral<T>::value, Handle>::type sub(const T offset) const
		{
			return this->as<std::uintptr_t>() - offset;
		}

		//get a pointer by the current pointer
		Handle dereference()
		{
			return this->get<std::uintptr_t>();
		}

		//transform the assembler pointer to a normal pointer
		template <typename T>
		Handle rip(const T ipoffset) const
		{
			T a = 0;
			#ifdef  DEBUG
			a = 4;
			#endif //  DEBUG

			return this->add(ipoffset + a).add(this->get<int32_t>());
		}

		//rebase the pointer
		Handle translate(const Handle fromBase, const Handle toBase) const
		{
			return toBase.add(this->as<std::intptr_t>() - fromBase.as<std::intptr_t>());
		}

		Handle toRVA(const Handle base) {
			return translate(base, std::uintptr_t(0));
		}

		Handle fromRVA(const Handle base) {
			return translate(std::uintptr_t(0), base);
		}
#ifdef _MEMORYAPI_H_
		bool protect(const std::size_t size, const std::uint32_t newProtect, const std::uint32_t * oldProtect)
		{
			return VirtualProtect(this->as<void*>(), size, (DWORD)newProtect, (DWORD*)& oldProtect) == TRUE;
		}

		bool nop(const std::size_t size)
		{
			std::uint32_t oldProtect;

			if (this->protect(size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				std::memset(this->as<void*>(), 0x90, size);

				this->protect(size, oldProtect, nullptr);

				return true;
			}

			return false;
		}

		//set a new data from
		inline bool set(const void* data, const std::size_t size)
		{
			std::uint32_t oldProtect;

			if (this->protect(size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				std::memcpy(this->as<void*>(), data, size);

				//this->protect(size, oldProtect, nullptr);

				return true;
			}

			return false;
		}

		//copy the current data to
		inline bool copyTo(void* data, const std::size_t size)
		{
			std::uint32_t oldProtect;

			if (this->protect(size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				std::memcpy(data, this->as<const void*>(), size);

				//this->protect(size, oldProtect, nullptr);

				return true;
			}

			return false;
		}

		template <typename T>
		inline void write(const T value)
		{
			static_assert(std::is_trivially_copyable<T>::value, "Type is not trivially copyable");

			this->as<T&>() = value;
		}

		/*
		template <typename... T>
		void write_args(const T... args)
		{
			std::uintptr_t off = 0;

			(void)std::initializer_list<int>
			{
				0, (this->add(off).write(args), off += sizeof(args))...
			};
		}

		template <typename T>
		bool write_vp(const T value)
		{
			std::uint32_t oldProtect;

			auto size = sizeof(value);

			if (this->protect(size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				this->write(value);

				this->protect(size, oldProtect, nullptr);

				return true;
			}

			return false;
		}

		template <typename... T>
		bool write_args_vp(const T... args)
		{
			std::uint32_t oldProtect;

			auto size = std::valarray<std::size_t>({ sizeof(args)... }).sum();

			if (this->protect(size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				this->write_args(args...);

				this->protect(size, oldProtect, nullptr);

				return true;
			}

			return false;
		}
		*/
#endif
	};

	/*
		Manage region in memory
	*/
	class Region
	{
	protected:
		Handle      _base;
		std::size_t _size;

	public:
		Region(Handle base, std::size_t size)
			: _base(base)
			, _size(size)
		{ }

		Handle base() const
		{
			return this->_base;
		}

		//get size of the region in bytes
		std::size_t size() const
		{
			return this->_size;
		}

		//get handle of the end of the region
		Handle end() const
		{
			return this->add(this->size());
		}

		//check the address contained in the region
		bool contains(const Handle address) const
		{
			return (address >= this->base()) && (address < this->end());
		}

		//get the address from base+offset
		template <typename T>
		Handle add(const T offset) const
		{
			return this->base().add(offset);
		}

		//get distance between the region base and the pointer in bytes
		Handle distance(const Handle pointer) const
		{
			return pointer.as<std::uintptr_t>() - this->base().as<std::uintptr_t>();
		}

		//replace the region with the pointer region
		Handle memcpy(const Handle pointer)
		{
			return std::memcpy(base().as<void*>(), pointer.as<const void*>(), size());
		}

		//set the value
		Handle memset(const std::uint8_t value)
		{
			return std::memset(base().as<void*>(), value, size());
		}

		std::string to_hex_string(bool padded = false)
		{
			static const char* hexTable = "0123456789ABCDEF";

			std::stringstream stream;

			for (std::size_t i = 0; i < size(); ++i)
			{
				if (i && padded)
				{
					stream << ' ';
				}

				stream << hexTable[(base().as<const std::uint8_t*>()[i] >> 4) & 0xF];
				stream << hexTable[(base().as<const std::uint8_t*>()[i] >> 0) & 0xF];
			}

			return stream.str();
		}
	};




#ifdef _WINNT_
	/*
		Work with .dll and .exe modules
	*/
	class Module : public Region
	{
	protected:
		Module(Handle base)
			: Region(base, base.add(base.as<IMAGE_DOS_HEADER&>().e_lfanew).as<IMAGE_NT_HEADERS&>().OptionalHeader.SizeOfImage)
		{ }

	public:
		HMODULE getHMODULE() {
			return this->base().as<HMODULE>();
		}

		static Module named(const char* name)
		{
			return Module(GetModuleHandleA(name));
		}

		static Module named(const wchar_t* name)
		{
			return Module(GetModuleHandleW(name));
		}

		static Module named(const std::nullptr_t)
		{
			return Module::named(static_cast<char*>(nullptr));
		}

		//get the main .exe module (for example, GTA5.exe)
		static Module main()
		{
			return Module::named(nullptr);
		}
	};
#endif

	//Object & Function interface
	class IObject
	{
	public:
		IObject() = default;

		IObject(Handle handle) {
			this->m_handle = handle;
		}

		bool isValid()
		{
			return this->m_handle != 0;
		}

		Handle getHandle()
		{
			return this->m_handle;
		}
	protected:
		Handle m_handle = nullptr;
	};


	template <typename T>
	class Object : public IObject
	{
	public:
		Object() = default;
		Object(Handle handle) : IObject(handle) { ; }

		//get value of the object
		T get()
		{
			return getHandle().get<T>();
		}

		//get value of the object
		T operator*()
		{
			return get();
		}

		//get pointer to the object
		T* operator&()
		{
			return getHandle().as<T*>();
		}

		//get T object by uniary operation + (for IDynStructure)
		T operator+()
		{
			return getHandle();
		}

		//get void* object
		operator void* ()
		{
			return (void*)getHandle();
		}

		//copy 1 object to 2 object by value(obj1 = obj2)
		Object& operator=(Object& data)
		{
			set(&data);
			return *this;
		}

		//copy data to object by pointer(obj = &struct, obj1 = &obj2)
		Object& operator=(const T* data)
		{
			this->m_handle = data;
			return *this;
		}

		//copy data to object by data(obj = 5, obj = struct)
		Object& operator=(T data)
		{
			set(&data);
			return *this;
		}

		//set a handle
		Object& operator=(const Memory::Handle handle)
		{
			this->m_handle = handle;
			return *this;
		}

		//set value to the object by pointer
		void set(const T* data, std::size_t size = sizeof(T))
		{
			this->getHandle().set(data, size);
		}

		//set value to the object(int, float, DWORD64) (not struct and more 8 bytes data if T is not a pointer!)
		void set(T value)
		{
			if constexpr (std::is_pointer<T>::value) {
				this->getHandle().set(&value, sizeof(T));
			}
			else {
				DWORD64 temp = (DWORD64)value;
				this->getHandle().set(&temp, sizeof(T));
			}
		}

	};

	template <typename T> class Function;
	template<typename R, typename... Args>
	class Function<R(Args ...)> : public IObject
	{
		typedef R(__fastcall *FT)(Args ...);
	public:
		Function() = default;
		Function(Handle handle) : IObject(handle) { ; }
		
		//execute the function
		R operator () (Args... args)
		{
			return getHandle().as<FT>()(args...);
		}
	};
	
	

	template <typename T> class FunctionHook;
	template<typename R, typename... Args>
	class FunctionHook<R(Args ...)>
	{
		typedef R(__fastcall *FT)(Args ...);
		using Func = Function<R(Args ...)>;
	public:
		FunctionHook() = default;
		FunctionHook(Func handle) : m_func(handle) { ; }
		FunctionHook(FT handle) : m_func(Func(handle)) { ; }
		FunctionHook(Handle handle) : m_func(handle) { ; }
		
		//install a hook on the function
		bool hook(bool enable = true)
		{
			if (getHookFunc() == nullptr || getFunc() == nullptr) {
				return false;
			}
			if (MH_CreateHook(getFunc(), getHookFunc(), reinterpret_cast<LPVOID*>(&m_funcOrig)) != MH_OK) {
				return false;
			}
			if (enable) {
				this->enable();
			}
			return true;
		}

		//install a hook on the function with
		bool hookWith(FT fn, bool enable = true)
		{
			setFunctionHook(fn);
			return hook(enable);
		}

		//install a hook on the function with nothing
		bool hookWithNothing(bool enable = true)
		{
			static FT emptyFT = [](Args...) -> R {
				if constexpr (!std::is_same<R, void>::value) {
					return NULL;
				}
			};
			setFunctionHook(emptyFT);
			return hook(enable);
		}

		//set a hook function
		void setFunctionHook(FT fn)
		{
			m_funcHook = fn;
		}

		//get origin function without any changes
		FT getOrigFunction()
		{
			return m_funcOrig;
		}

		//get a new function replaced origin
		FT getHookFunction()
		{
			return m_funcHook;
		}

		//get an entry function
		Func getFunction()
		{
			return m_func;
		}

		//call the origin function
		R executeOrigFunc(Args... args)
		{
			if constexpr (!std::is_same<R, void>::value) {
				if (getOrigFunction() == nullptr)
					return NULL;
				return m_funcOrig(args...);
			}
			else {
				if (getOrigFunction() == nullptr)
					return;
				m_funcOrig(args...);
			}
		}

		//call the hook function
		R executeHookFunc(Args... args)
		{
			if constexpr (!std::is_same<R, void>::value) {
				if (getHookFunction() == nullptr)
					return NULL;
				return m_funcHook(args...);
			}
			else {
				if (getHookFunction() == nullptr)
					return;
				m_funcHook(args...);
			}
		}
		
		//hook on
		void enable()
		{
			MH_EnableHook(getFunc());
		}

		//hook off
		void disable()
		{
			MH_DisableHook(getFunc());
		}
	private:
		Func m_func = nullptr;
		FT m_funcHook = nullptr;
		FT m_funcOrig = nullptr;

		LPVOID getFunc()
		{
			return getFunction().getHandle().as<LPVOID>();
		}

		LPVOID getHookFunc()
		{
			return reinterpret_cast<LPVOID>(getHookFunction());
		}
	};
};