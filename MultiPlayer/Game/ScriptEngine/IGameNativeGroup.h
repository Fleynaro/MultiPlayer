#pragma once

#include "IGameNative.h"
#include "IGameHashes.h"
#include "Natives/types.h"


/*
	Regex replace all:
	Source:			static (\w+\*?) (\w+)\(([\w, \*]*)\) { [\w\s<>\*]+\(([0-9abcedfx]+).+
	Destinition 1:	static GameNative<$1($3), $4> $2;
	Destinition 2:	NATIVE($2)
	Destinition 3:	&PED::$2,
*/

class IGameNativeHelper
{
public:
	//init native
	static void initNative(IGameNative* native)
	{
		auto h = getHashNativeHandler(
			native->getHash()
		);
		if (h == nullptr)
			return;

		native->bindTo(
			h->getHandler()
		);

		//add native to search map
		m_natives[native->getHash()] = native;
	}

	//get hash native handler by old hash(static)
	static GameHashNativeHandler* getHashNativeHandler(IGameNative::Hash hash)
	{
		auto h1 = GameHashAdapter::getList()->getHash(hash);
		if (h1 == nullptr) {
			//throw ex
			return nullptr;
		}

		auto h2 = GameHashNativeHandler::getList().getHash(
			h1->getNewHash()
		);
		if (h2 == nullptr) {
			//throw ex
			return nullptr;
		}

		return h2;
	}
	
	//get native by old hash(static)
	static IGameNative* getNative(IGameNative::Hash hash) {
		return m_natives[hash];
	}

	//get all natives
	static std::map<IGameNative::Hash, IGameNative*>& getNatives() {
		return m_natives;
	}
private:
	static inline std::map<IGameNative::Hash, IGameNative*> m_natives;
};


template<typename T>
class IGameNativeGroup
{
public:
	using group = std::vector<IGameNative*>;

	static void initNatives()
	{
		for (auto native : getNatives()) {
			IGameNativeHelper::initNative(native);
		}
	}

	//get all natives in the group
	static group& getNatives() {
		return m_natives;
	}
protected:
	static group m_natives;

	static void addNativeList(group& natives)
	{
		for (auto native : natives) {
			addNative(native);
		}
	}

	static void addNative(IGameNative* native)
	{
		m_natives.push_back(native);
	}
};


inline Memory::Handle& operator""_handler(IGameNative::Hash hash)
{
	return IGameNativeHelper::getHashNativeHandler(hash)->getHandler();
}



//init game natives
#define GAME_NATIVE_INIT(group, name) decltype(##group::##name) ##group::##name(#name);