#pragma once


#include "main.h"


template <std::size_t Size>
class IStack
{
	using ANY = uint64_t;
public:
	IStack() = default;

	template <typename T>
	T get(int index) {
		return reinterpret_cast<const T&>(this->data[index]);
	}

	template <typename T>
	IStack set(int index, const T& value) {
		reinterpret_cast<T&>(this->data[index]) = value;
		return *this;
	}

	template <uint32_t index, typename T>
	inline static void Push(IStack* st, const T& value)
	{
		st->set(index, value);
	}

	template <uint32_t index, typename... TArgs, typename T>
	inline static void Push(IStack* st, const T& value, TArgs... values)
	{
		Push<index>(st, value);
		Push<index + 1>(st, values...);
	}

	template <typename... TArgs>
	IStack Push(const TArgs& ... values)
	{
		Push<0>(values...);
		return *this;
	}

	template <int Index, typename... TArgs>
	IStack Push(const TArgs& ... values)
	{
		Push<Index>(this, values...);
		return *this;
	}
private:
	ANY data[Size];
};