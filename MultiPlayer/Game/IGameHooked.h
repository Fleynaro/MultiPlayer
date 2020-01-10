#pragma once

#include "Game/IGameHook.h"



class IGameHooked
{
public:
	virtual void InstallHook(IGameHook* hook)
	{
		hook->Init(this);
		hook->Install();
	}

	virtual void RemoveHook(IGameHook* hook)
	{
		hook->Init(this);
		hook->Remove();
	}
};


class IGameStaticHooked
{
public:
	static void InstallHook(IGameHook* hook)
	{
		hook->Install();
	}

	static void RemoveHook(IGameHook* hook)
	{
		hook->Remove();
	}
};