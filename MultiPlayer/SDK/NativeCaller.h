#pragma once



#include "API.h"


template <typename T> class Native;
template<typename R, typename... Args>
class Native<R(Args ...)>
{
public:
	static constexpr bool isReturnedValue = !std::is_same<R, void>::value;

	static R call(IGameNative* native, Args... args)
	{
		if constexpr (isReturnedValue) {
			return native->execute<R>(args...);
		}
		else {
			native->execute<R>(args...);
		}
	}
};

/*
template<
	typename R,
	typename... Args,
	uint64_t hash,
	class T = GameNative<R(Args...), hash>
>
static R CallNative(T& native, Args... args)
{
	if constexpr (!std::is_same<R, void>::value) {
		return native->execute<R>(args...);
	}
	else {
		native->execute<R>(args...);
	}
}*/

namespace SDK
{
	template<typename T, typename... Args>
	static auto Call(const T& native, Args... args) {
		using Native_t = ::Native<typename T::Sig>;
		if constexpr (Native_t::isReturnedValue) {
			return Native_t::call((IGameNative*)& native, args...);
		}
		else {
			Native_t::call((IGameNative*)& native, args...);
		}
	}
};