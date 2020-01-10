#pragma once


#include "IGameHook.h"


//modules needed be hooked
#include "GameScripts.h"
#include "GamePool.h"
#include "GameUpdate.h"
#include "GameExit.h"
#include "GameInput.h"
#include "GameCursorPointer.h"
#include "DirectX/Direct3D11.h"
#include "ScriptEngine/GameScriptEngine.h"
#include "MultiPlayer/GameStartLoad.h"
#include "MultiPlayer/GameRemoveSingleElements.h"


class IGameVersionHook
{
public:
	virtual IGameHook* getPool() = 0;
	virtual IGameHook* getStructure() = 0;
	virtual IGameHook* getGameScripts() = 0;
	virtual IGameHook* getUpdate() = 0;
	virtual IGameHook* getExit() = 0;
	virtual IGameHook* getInput() = 0;
	virtual IGameHook* getD3D() = 0;
	virtual IGameHook* getStartLoad() = 0;
	virtual IGameHook* getCursorPointer() = 0;
	virtual IGameHook* getRemoveSingleElems() = 0;
	virtual IGameHook* getScriptEngine() = 0;
	virtual void setScriptEngineVersion() = 0;
};



class GameVersionHook_141 : public IGameVersionHook
{
public:
	GameVersionHook_141()
	{
		//can use pattern Decorator
		new GameScriptsHook_Gen;
		new GamePoolHook_Gen;
		new GameObjectHook_Gen;
		new GameUpdateHook_Gen;
		new GameExitHook_Gen;
		new GameInputHook_Gen;
		new Direct3D11Hook_Gen;
		new GameStartLoadHook_Gen;
		new GameCursorPointerHook_Gen;
		new GameRemoveSingleElementsHook_Gen;
		new GameScriptEngineHook_Gen;
	}

	IGameHook* getPool() override {
		return GamePoolHook_Gen::GetInstancePtr();
	}

	IGameHook* getStructure() override {
		return GameObjectHook_Gen::GetInstancePtr();
	}

	IGameHook* getGameScripts() override {
		return GameScriptsHook_Gen::GetInstancePtr();
	}

	IGameHook* getUpdate() override {
		return GameUpdateHook_Gen::GetInstancePtr();
	}

	IGameHook* getExit() override {
		return GameExitHook_Gen::GetInstancePtr();
	}

	IGameHook* getInput() override {
		return GameInputHook_Gen::GetInstancePtr();
	}

	IGameHook* getD3D() override {
		return Direct3D11Hook_Gen::GetInstancePtr();
	}

	IGameHook* getStartLoad() override {
		return GameStartLoadHook_Gen::GetInstancePtr();
	}

	IGameHook* getCursorPointer() override {
		return GameCursorPointerHook_Gen::GetInstancePtr();
	}

	IGameHook* getRemoveSingleElems() override {
		return GameRemoveSingleElementsHook_Gen::GetInstancePtr();
	}

	IGameHook* getScriptEngine() override {
		return GameScriptEngineHook_Gen::GetInstancePtr();
	}

	void setScriptEngineVersion() override {
		GameHashAdapter::setList(new GameHashes("V141"));
	}
};