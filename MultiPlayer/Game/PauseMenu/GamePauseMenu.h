#pragma once






#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"




class GamePauseMenu : public IGameStaticHooked
{
public:

};



class GamePauseMenu_Gen : public IGameHook, public ISingleton<GamePauseMenu_Gen>
{
public:
	void Install()
	{

	}

	void Remove()
	{

	}
};