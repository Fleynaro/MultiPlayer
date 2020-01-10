#pragma once



#include <fstream>
#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Game/GameAppInfo.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"
#include "Utility/Resource.h"




class GameStartLoad : public IGameStaticHooked
{
	friend class GameStartLoadHook_Gen;
public:
	//structure for GameSaveInfo
	class CGameSaveInfo : public Memory::IDynStructure<CGameSaveInfo>
	{
	public:
		enum FIELD {
			data,
			size
		};

		static void init() {
			setFieldOffset(data, 0x18);
			setFieldOffset(size, 0x30);
		}

		CGameSaveInfo(Memory::Handle base) : IDynStructure(base) {}

		void* getData() {
			return getFieldPtr<void*>(data);
		}

		uint32_t getSize() {
			return getFieldValue<uint32_t>(size);
		}

		//set a new game save by value
		void setData(void* Data, std::size_t Size) {
			//setFieldValue<void>(data, Data, Size);
			getField(data).dereference().set(Data, Size);
		}

		//set a new game save by pointer
		void setData(void* Data) {
			std::uintptr_t addr = Memory::Handle(Data).as<std::uintptr_t>();
			setFieldValue<std::uintptr_t>(data, &addr);
		}

		//set size of a new game save
		void setSize(uint32_t Size) {
			setFieldValue<uint32_t>(size, &Size);
		}
	};

	//global vars and functions
	inline static Memory::Object<CGameSaveInfo> GameSaveInfo;
	inline static Memory::Function<bool(bool p1, DWORD64 p2, bool p3)> LoadGeneral;
	inline static Memory::Function<bool(void* p1, bool p2)> LoadSave;
	inline static Memory::Function<void()> LoadEnd;

	inline static std::string pathToSaveData; //for external file
	inline static BINARY_Res SavaDataResource; //for internal dll resource

	//save <game save data> to a directory on the path
	static bool saveOwnSaveData(std::string path)
	{
		std::ofstream F(path, std::ios::binary);
		if (F.is_open()) {
			F.write(
				(char*)(+GameSaveInfo).getData(),
				(+GameSaveInfo).getSize()
			);
			F.close();
			return true;
		}
		return false;
	}

	//load save data
	static bool loadOwnSaveData(std::string path, int &Size, byte* &Data)
	{
		std::ifstream F(path, std::ios::binary | std::ios::ate);
		if (F.is_open()) {
			Size = (int)F.tellg();

			Data = new byte[Size];
			F.read((char*)Data, Size);
			F.close();
			return true;
		}
		return false;
	}

	//load save data as resource
	static bool loadOwnSaveDataAsResource(BINARY_Res& R, int& Size, byte*& Data)
	{
		if (!R.isLoaded()) {
			return false;
		}
		Size = (int)R.getSize();
		Data = R.getData();

		byte* data = new byte[Size];
		memcpy(data, Data, Size);

		Data = data;
		R.free();
		return true;
	}

	//change global game save struct setting own save data
	static bool setOwnSaveData(BINARY_Res& R)
	{
		int Size = 0;
		byte* Data = nullptr;
		if (loadOwnSaveDataAsResource(R, Size, Data)) {
			(+GameSaveInfo).setSize(Size);
			(+GameSaveInfo).setData(Data);
			return true;
		}
		return false;
	}

	//called once when loading screen shown
	static void StartLoadHook(DWORD64 p1, DWORD64 p2)
	{
		//set own game save
		setOwnSaveData(SavaDataResource);

		GlobalVar2 = GlobalVar1;
		LoadGeneral(true, p2, true);

		//load own game save
		LoadSave((void*)GameSaveInfo, false);

		LoadEnd();
	}
	inline static Memory::FunctionHook<decltype(StartLoadHook)> StartLoad;

private:
	inline static Memory::Object<int> GlobalVar1;
	inline static Memory::Object<int> GlobalVar2;
};



class GameStartLoadHook_Gen : public IGameHook, public ISingleton<GameStartLoadHook_Gen>
{
public:
	void Install()
	{
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("48 89 5C 24 08 57 48 83 EC 20 E8 ?? ?? ?? ?? EB"),//0F
				&StartLoad
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("00 00 B1 01 E8 *?? ?? ?? ?? B1 01 E8 ?? ?? ?? ?? E8"),//?? ?? ?? ?? 83 F8 02 75
				&LoadGeneral,
				new Memory::FoundPattern(
					Memory::Pattern("07 33 C9 E8 *?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 48 8B 5C"),//24 30 8D 41 FC 83 F8 01 0F 47 CF
					&LoadGeneral
				)
			)
		);

		//including gameSaveInfo
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("77 23 48 8D 0D *?? ?? ?? ?? B2 01 E8 ?? ?? ?? ?? 84"),//84 C0 75 07 BB 02 00 00 00
				&LoadSave
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("40 84 FF 75 0C 8B CB E8 *?? ?? ?? ??"),//E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 02 00 00 00
				&LoadEnd
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("00 00 8B 05 *?? ?? ?? ?? 33 FF 89 05 ?? ?? ?? ?? 85"),//DB 0F 85 8D 00 00 00 B1 01 E8
				&globalVars
			)
		);

		//hook stat loading
		StatLoad instance;
	}

	static void StartLoad(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameStartLoad::StartLoad = pattern.getResult();
		GameStartLoad::StartLoad.setFunctionHook(GameStartLoad::StartLoadHook);
		GameStartLoad::StartLoad.hook();

		GameStartLoad::SavaDataResource = BINARY_Res("SAVE", GameAppInfo::GetInstancePtr()->getDLL());
		try {
			GameStartLoad::SavaDataResource.load();
		}
		catch (int t) {
			t = 3;
			//...
		}
	}

	static void LoadGeneral(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameStartLoad::LoadGeneral = pattern.getResult().rip(4);
	}

	static void LoadSave(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameStartLoad::LoadSave = pattern.getResult().add(7).rip(4);
		GameStartLoad::GameSaveInfo = pattern.getResult().rip(4);
	}

	static void LoadEnd(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameStartLoad::LoadEnd = pattern.getResult().rip(4);
	}

	static void globalVars(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		GameStartLoad::GlobalVar1 = pattern.getResult().rip(4);
		GameStartLoad::GlobalVar2 = pattern.getResult().add(8).rip(4);
	}

	class StatLoad
	{
	public:
		enum CATEGORY
		{
			SimpleVariables,
			MiniMap,
			PlayerPed,
			ExtraContent,
			Garages,
			Stats,
			StuntJumps,
			RadioStations,
			Doors,
			Camera,

			//exist to get count
			Count
		};
		inline static Memory::FunctionHook<void(const char*, void*)> m_functs[Count];

		StatLoad()
		{
			GameHookList::Add(
				new Memory::FoundPattern(
					Memory::Pattern("20 48 8B CB E8 ?? ?? ?? ?? 48 8D 54 24 20 48 8D 0D ?? ?? ?? ?? E8 *??"),
					&StatCategoriesToLoad
				)
			);
		}

		static void StatCategoriesToLoad(Memory::FoundPattern& pattern)
		{
			if (!pattern.hasResult()) {
				throw GameHookException(
					GAME_HOOK_EXCEPTION_STD
				);
				return;
			}

			std::size_t begin = 0;//22
			for(std::size_t fn = SimpleVariables; fn <= Camera; fn++) {
				setFunction(static_cast<CATEGORY>(fn),
					pattern.getResult().add(begin + 17LL * fn).rip(4)
				);
			}

			Disable();
		}

		static void setFunction(CATEGORY index, const Memory::Handle handle) {
			m_functs[index] = handle;
			m_functs[index].hookWithNothing(false);
		}

		//disable a load category
		static void DisableStatCategoryToLoad(CATEGORY index)
		{
			m_functs[index].enable();
		}

		//disable all unuseful
		static void Disable()
		{
			for (int fn = SimpleVariables; fn <= Camera; fn++) {
				CATEGORY func = static_cast<CATEGORY>(fn);

				if (fn != SimpleVariables && fn != PlayerPed) {
					DisableStatCategoryToLoad(func);
				}
			}
		}
	};

	void Remove()
	{
	}
};