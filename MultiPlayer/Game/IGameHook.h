#pragma once



//need to hook functions and variables
#include "Utility/MemoryHandle.h"
#include "Utility/Pattern.h"
#include "GameException.h"


#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define GAME_HOOK_EXCEPTION_STD std::string(__FUNCTION__) + " in file " + __FILENAME__, &pattern, GameHookException::NOT_FOUND


class IGameHooked;
class IGameHook
{
public:
	virtual void Init(IGameHooked* gameObj)
	{
		m_gameObj = gameObj;
	}

	virtual void Install() = 0;
	virtual void Remove() = 0;
protected:
	IGameHooked* m_gameObj = nullptr;
};