#pragma once

#include "Game/IGameHook.h"
#include "Utility/IException.h"



class GameHookException : public IGameException
{
public:
	enum REASON {
		NOT_DEFINED,
		NOT_FOUND
	};

	GameHookException(std::string desc, const Memory::FoundPattern* pattern, REASON reason = NOT_DEFINED) : IGameException(desc)
	{
		m_pattern = pattern;
		m_reason = reason;
	}

	REASON getReason() {
		return m_reason;
	}

	const Memory::FoundPattern* getFoundPattern() {
		return m_pattern;
	}
private:
	const Memory::FoundPattern* m_pattern = nullptr;
	REASON m_reason = NOT_DEFINED;
};