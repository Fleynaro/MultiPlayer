#pragma once


#include "Game/IGameHook.h"
#include "Game/GameAppInfo.h"

#include "Utility/FileWrapper.h"


class GameHookList
{
public:
	using list = std::list<Memory::FoundPattern*>;
	
	static void Add(Memory::FoundPattern* pattern)
	{
		m_patterns.push_back(pattern);
	}

	static void Add(list patterns)
	{
		for (auto const pattern : patterns) {
			Add(pattern);
		}
	}

	static void Complete()
	{
		LoadOffsetsFromCacheFile();

		Memory::FoundPatternList p_list(
			m_patterns
		);
		p_list.scan();

		SaveOffsetsToCacheFile();
		Clear();
	}

	static Memory::FoundPattern* getFoundPatternByBytes(std::string bytes) {
		for (auto fpattern : m_patterns) {
			if (fpattern->getPattern().getStr() == bytes) {
				return fpattern;
			}
		}
		return nullptr;
	}

	static void LoadOffsetsFromCacheFile()
	{
		if (!m_cache.exists())
			return;

		FS::JsonFileDesc cacheFile(m_cache, std::ios::in);
		if (cacheFile.isOpen()) {
			json cache = cacheFile.getData();
			if (!cache["items"].is_array()) {
				return;
			}

			for (auto it : cache["items"]) {
				if (!it.is_array() || !it[0].is_string() || !it[1].is_number_integer())
					continue;
				std::string bytes = it[0].get<std::string>();
				Memory::Handle offset = it[1].get<std::uintptr_t>();

				Memory::FoundPattern* fpattern = getFoundPatternByBytes(bytes);
				if (fpattern != nullptr) {
					auto addr = offset.fromRVA(
						Memory::Module::main().base()
					).sub(fpattern->getPattern().getBegin());
					if (fpattern->considerMatch(addr.as<std::uintptr_t>())) {
						fpattern->successMatch(addr.as<std::uintptr_t>());
					}
				}
			}
		}
	}

	static void SaveOffsetsToCacheFile()
	{
		json cache;
		cache["version"] = "v1.4.1";
		
		int idx = 0;
		for (auto fpattern : m_patterns) {
			if (!fpattern->hasResult())
				continue;
			cache["items"][idx][0] = fpattern->getPattern().getStr();
			cache["items"][idx][1] = fpattern->getResult().toRVA(Memory::Module::main().base()).as<std::uintptr_t>();
			idx++;
		}

		FS::JsonFileDesc cacheFile(m_cache, std::ios::out);
		if (cacheFile.isOpen()) {
			cacheFile.setData(cache);
		}
	}

	static void Clear()
	{
		for (auto pattern : m_patterns) {
			delete pattern;
		}
		m_patterns.clear();
	}

	inline static FS::File m_cache;
private:
	inline static list m_patterns;
};
