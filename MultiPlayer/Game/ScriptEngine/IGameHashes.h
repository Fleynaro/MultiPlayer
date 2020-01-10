#pragma once


#include "IGameNative.h"


/*
	Regex to replace all:
	Source:			(0x[\dabcdef]{2,16}), (0x[\dabcdef]{2,16}),
	Destinition:	["$1", "$2"],
*/



//native hash interface
class IGameHash
{
public:
	IGameHash(IGameNative::Hash hash)
		: m_hash(hash)
	{}

	IGameNative::Hash getHash() const {
		return m_hash;
	}
private:
	IGameNative::Hash m_hash;
};



//hash class manager
template<typename T = IGameHash>
class IGameHashes
{
public:
	IGameHashes() = default;

	T* getHash(IGameNative::Hash hash)
	{
		auto it = std::find_if(m_hashes.begin(), m_hashes.end(), [&](const T * h) {
			return h->getHash() == hash;
			});
		if (it == m_hashes.end())
			return nullptr;
		return *it;
	}
	

	using list = std::vector<T*>;

	//add hash list
	void addHashList(list & hashes)
	{
		for (auto hash : hashes) {
			addHash(hash);
		}
	}

	//add hash to list
	void addHash(T * hash)
	{
		m_hashes.push_back(hash);
	}

	//get count
	std::size_t getCount()
	{
		return m_hashes.size();
	}
private:
	list m_hashes;
};



//make suitability between old hash and new hash
class GameHashAdapter : public IGameHash
{
public:
	GameHashAdapter(IGameNative::Hash oldHash, IGameNative::Hash newHash)
		: IGameHash(oldHash), m_newHash(newHash)
	{}
	
	IGameNative::Hash getNewHash() const {
		return m_newHash;
	}
	
	static IGameHashes<GameHashAdapter>* getList() {
		return m_adapterList;
	}

	static void setList(IGameHashes<GameHashAdapter>* list) {
		m_adapterList = list;
	}
private:
	IGameNative::Hash m_newHash;

	inline static IGameHashes<GameHashAdapter>* m_adapterList;
};




//make suitability between new hash and native handler
class GameHashNativeHandler : public IGameHash
{
public:
	GameHashNativeHandler(IGameNative::Hash newHash, Memory::Handle handler)
		: IGameHash(newHash), m_handler(handler)
	{}

	Memory::Handle& getHandler() {
		return m_handler;
	}

	static IGameHashes<GameHashNativeHandler>& getList() {
		return m_nativeHandlerList;
	}
private:
	Memory::Handle m_handler;

	inline static IGameHashes<GameHashNativeHandler> m_nativeHandlerList;
};




#include "Utility/Resource.h"
#include "Utility/Generic.h"
#include "Game/GameAppInfo.h"
//load hashes from dll json resource
class GameHashes : public IGameHashes<GameHashAdapter>
{
	std::string m_version;

	enum HASH_JSON_FORMAT {
		OLD_HASH,
		NEW_HASH
	};
public:
	GameHashes(std::string version) {
		m_version = "HASHLIST_" + version;
		loadHashes();
	}

	void loadHashes() {
		JSON_Res res(m_version, GameAppInfo::GetInstancePtr()->getDLL());
		res.load();
		if (!res.isLoaded()) {
			//throw ex
			return;
		}

		json data = res.getData();
		for (auto &it : data["hashes"]) {
			addHash(
				new GameHashAdapter(
					Generic::String::HexToNumber(it[OLD_HASH].get<std::string>()),
					Generic::String::HexToNumber(it[NEW_HASH].get<std::string>())
				)
			);
		}
	}
};