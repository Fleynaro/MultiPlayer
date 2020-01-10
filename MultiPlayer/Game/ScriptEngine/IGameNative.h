#pragma once

#include "main.h"
#include "Utility/IStack.h"
#include "Utility/MemoryHandle.h"
#include "Utility/Generic.h"


//Native argument stack
class GameNativeArgStack : public IStack<32u>
{
};

//Native return stack
class GameNativeRetStack : public IStack<3u>
{
};

//Native return stack
class GameNativeScrContext
{
private:
	GameNativeRetStack* const m_pReturns;
	uint32_t m_nArgCount;
	GameNativeArgStack* const m_pArgs;
	uint32_t m_nDataCount;
	uint64_t reservedSpace[24] = {};
public:
	GameNativeScrContext(GameNativeRetStack* returnStack, GameNativeArgStack* argStack)
		: m_pReturns(returnStack)
		, m_nArgCount(0)
		, m_pArgs(argStack)
		, m_nDataCount(0) {}

	GameNativeScrContext()
		: GameNativeScrContext(new GameNativeRetStack, new GameNativeArgStack)
	{}

	//push arguments to the native stack
	template <typename... TArgs>
	void pushArgs(TArgs... values)
	{
		m_pArgs->Push(values...);
		m_nArgCount = sizeof...(TArgs);
	}

	template <typename T>
	void setArg(uint32_t index, const T& value)
	{
		m_pArgs->set(index, value);
		if (index + 1 > m_nArgCount) {
			m_nArgCount = index + 1;
		}
	}
	
	uint64_t getResult(uint32_t index)
	{
		return m_pReturns->get<uint64_t>(index);
	}

	template <typename T>
	void setResult(const T& value)
	{
		m_pReturns->Push(value);
	}

	//get result when handler has called
	template <typename T>
	T getResult() const {
		return m_pReturns->get<T>(0);
	}

	uint32_t getArgCount() const {
		return m_nArgCount;
	}

	void reset() {
		m_nArgCount = 0;
		m_nDataCount = 0;
	}
};





class IGameNative
{
public:
	using Hash = uint64_t;
	using Handler = Memory::Function<void* (GameNativeScrContext*)>;

	IGameNative(std::string name)
		: m_name(name)
	{}

	void bindTo(Memory::Handle handler) {
		m_handler = handler;
	}

	std::string getName() const {
		return m_name;
	}

	virtual Hash getHash() = 0;
	virtual std::string getSignature() = 0;

	std::string getHashStr() {
		using namespace Generic::String;
		auto result = ToUpper(NumberToHex(getHash()));
		while (result.length() < 16)
			result = "0" + result;

		return "0x" + result;
	}

	static GameNativeScrContext* getContext() {
		return &m_context;
	}

	template<typename R, typename... Args>
	R execute(Args... args)
	{
		getContext()->reset();
		getContext()->pushArgs(args...);
		execute();
		if constexpr (!std::is_same<R, void>::value) {
			return getContext()->getResult<R>();
		}
	}

	void execute() {
		m_handler(getContext());
	}

	Handler& getHandler() {
		return m_handler;
	}
protected:
	std::string m_name;
	Handler m_handler;

	inline static GameNativeScrContext m_context;
};


template <typename T, uint64_t hash> class GameNative;
template<typename R, typename... Args, uint64_t hash>
class GameNative<R(Args ...), hash> : public IGameNative
{
public:
	typedef R(Sig)(Args ...);
	
	GameNative(std::string name)
		: IGameNative(name)
	{}
	
	//execute the function
	R operator () (Args... args)
	{
		if constexpr (!std::is_same<R, void>::value) {
			return execute<R>(args...);
		}
		else {
			execute<void>(args...);
		}
	}

	Hash getHash() override {
		return hash;
	}

	std::string getSignature() override {
		return typeid(R(*)(Args ...)).name();
	}
};