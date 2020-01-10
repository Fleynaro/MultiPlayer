#pragma once



#include "Utility/ISingleton.h"
#include "Utility/FileWrapper.h"

//main info about application (multiplayer)
class GameAppInfo : public ISingleton<GameAppInfo>
{
	HMODULE m_DLL;
public:
	GameAppInfo(HMODULE DLL) : m_DLL(DLL) {}

	//get the main dll of multiplayer
	HMODULE getDLL() {
		return m_DLL;
	}
	
	//get the main game .exe module
	HMODULE getMain() {
		return GetModuleHandle(NULL);
	}
	
	//get the main dll directory of multiplayer
	FS::Directory getDllDirectory() {
		return FS::File::getModule(getDLL()).getDirectory();
	}

	//get the main game .exe directory
	FS::Directory getMainDirectory() {
		return FS::File::getModule(getMain()).getDirectory();
	}
};