
#include "pch.h"

#include "main.h"

#include "Core/Core.h"

#include "Core/ScriptLang/JavaScript/JavaScriptContext.h"

#include "Utility/MemoryHandle.h"
#include "Utility/Pattern.h"

#include "Game/GameVersionHook.h"
#include "Game/GameHookList.h"
#include "Game/GameException.h"

#include "Game/GameAppInfo.h"

using namespace SE;


#include "Utility/VirtualKeyCodes.h"


enum PedTypes
{
	PED_TYPE_PLAYER_0,	// michael
	PED_TYPE_PLAYER_1,	// franklin
	PED_TYPE_NETWORK_PLAYER,	// mp character
	PED_TYPE_PLAYER_2,	// trevor
	PED_TYPE_CIVMALE,
	PED_TYPE_CIVFEMALE,
	PED_TYPE_COP,
	PED_TYPE_GANG_ALBANIAN,
	PED_TYPE_GANG_BIKER_1,
	PED_TYPE_GANG_BIKER_2,
	PED_TYPE_GANG_ITALIAN,
	PED_TYPE_GANG_RUSSIAN,
	PED_TYPE_GANG_RUSSIAN_2,
	PED_TYPE_GANG_IRISH,
	PED_TYPE_GANG_JAMAICAN,
	PED_TYPE_GANG_AFRICAN_AMERICAN,
	PED_TYPE_GANG_KOREAN,
	PED_TYPE_GANG_CHINESE_JAPANESE,
	PED_TYPE_GANG_PUERTO_RICAN,
	PED_TYPE_DEALER,
	PED_TYPE_MEDIC,
	PED_TYPE_FIREMAN,
	PED_TYPE_CRIMINAL,
	PED_TYPE_BUM,
	PED_TYPE_PROSTITUTE,
	PED_TYPE_SPECIAL,
	PED_TYPE_MISSION,
	PED_TYPE_SWAT,
	PED_TYPE_ANIMAL,
	PED_TYPE_ARMY
};


bool scriptEnable = false;


Vector2 GetResolution()
{
	int scr_w, scr_h;
	GRAPHICS::GET_SCREEN_RESOLUTION(&scr_w, &scr_h);
	return Vector2((float)scr_w, (float)scr_h);
}

void DrawScrText(const std::string& text, Vector2 pos, float scale, int font, const int rgba[4], bool outline = true, bool center = true)
{
	UI::SET_TEXT_FONT(font);
	UI::SET_TEXT_SCALE(scale, scale);
	UI::SET_TEXT_COLOUR(rgba[0], rgba[1], rgba[2], rgba[3]);
	UI::SET_TEXT_WRAP(0.f, 1.f);
	UI::SET_TEXT_CENTRE(center);
	if (outline) UI::SET_TEXT_OUTLINE(1);

	UI::BEGIN_TEXT_COMMAND_DISPLAY_TEXT("CELL_EMAIL_BCON");
	for (std::size_t i = 0; i < text.size(); i += 99)
	{
		UI::ADD_TEXT_COMPONENT_SUBSTRING_PLAYER_NAME(text.c_str() + i);
	}
	UI::ADD_TEXT_COMPONENT_INTEGER(10);
	UI::ADD_TEXT_COMPONENT_SUBSTRING_TEXT_LABEL("extra");
	
	UI::END_TEXT_COMMAND_DISPLAY_TEXT(pos.x, pos.y);
}

std::string statusText;
std::size_t statusTextDrawTicksMax;
bool statusTextGxtEntry;
void set_status_text(std::string str, std::size_t time = 2500, bool isGxtEntry = false)
{
	statusText = str;
	statusTextDrawTicksMax = timeGetTime() + time;
	statusTextGxtEntry = isGxtEntry;
}


//include SDK
#include "SDK/World/Ped/Ped.h"
#include "SDK/World/Vehicle/Vehicle.h"
#include "SDK/World/Ped/Weapon/Weapon.h"
#include "SDK/World/Bone.h"
#include "SDK/World/Ped/Task/TaskInvoker.h"
#include "SDK/Builder.h"





class Update1 : public IGameScriptContext, public ISingleton<Update1>
{
public:
	IGameScriptContext* getCopyInstance() override {
		return new Update1;
	}

	void OnInit() override
	{
		GameScriptEngine::initNatives();
		GameScriptEngine::registerScriptExecutingContext(this);
		set_status_text("~b~SCRIPT ENGINE INIT");

		auto input = new InputHandler1;
		input->setProxyNode(this);
		GameInput::addEventHandler(input);
		
		auto d3d = new D3D_Present2;
		//d3d->setProxyNode(this);
		//Direct3D11::addEventHandler(d3d);

		
		scriptEnable = true;
		GameScripts::terminateDisabledScripts();

		
	}

	bool off = false;

	void OnTick() override
	{
		const auto res = GetResolution();
		auto mBottomPos = Vector2((res.x / 2) / res.x, (res.y / res.y) - 0.049f);
		const int Color[4] = { 255, 255, 255, 255 };
		DrawScrText("TEST text 0", mBottomPos, 0.33f, 0, Color, true, true);

		mBottomPos.y *= 0;
		DrawScrText(u8"Here text 1 - это текст!", mBottomPos, 0.33f, 0, Color, true, true);
	}


	void PaintVehRandom(Vehicle veh)
	{
		if (!ENTITY::DOES_ENTITY_EXIST(veh)) return;

		int mainColor = GAMEPLAY::GET_RANDOM_INT_IN_RANGE(0, 160);
		int extraColor = GAMEPLAY::GET_RANDOM_INT_IN_RANGE(0, 160);

		VEHICLE::SET_VEHICLE_MOD_KIT(veh, 0);

		VEHICLE::SET_VEHICLE_MOD_COLOR_1(veh, 0, 0, 0);
		VEHICLE::SET_VEHICLE_MOD_COLOR_2(veh, 0, 0);

		VEHICLE::SET_VEHICLE_COLOURS(veh, mainColor, mainColor);

		VEHICLE::SET_VEHICLE_EXTRA_COLOURS(veh, extraColor, extraColor);
	}

	void teleport_to_location(Vector3 coords)
	{
		// get entity to teleport
		SE::Entity entity = PLAYER::PLAYER_PED_ID();
		if (PED::IS_PED_IN_ANY_VEHICLE(entity, 0))
			entity = PED::GET_VEHICLE_PED_IS_USING(entity);

		ENTITY::SET_ENTITY_COORDS_NO_OFFSET(entity, coords.x, coords.y, coords.z, 0, 0, 1);

		set_status_text("teleported");
	}

	class D3D_Present1 : public GameEventHandlerProxy<IGameEventD3D_Present>
	{
	public:
		Update1* getScriptContext() {
			return (Update1*)getProxy();
		}

		void OnPresent(UINT SyncInterval, UINT Flags) override
		{
			if (!getScriptContext()->off) {
				const auto res = GetResolution();
				auto mBottomPos = Vector2((res.x / 2) / res.x, (res.y / res.y) - 0.049f);
				const int Color[4] = { 255, 255, 255, 255 };
				DrawScrText("Here text 2", mBottomPos, 0.7f, 0, Color, false, true);
			}
		}
	};

	class D3D_Present2 : public IGameEventD3D_Present
	{
	public:
		void OnPresent(UINT SyncInterval, UINT Flags) override
		{
			const auto res = GetResolution();
			auto mBottomPos = Vector2((res.x / 2) / res.x, (res.y / res.y) - 0.049f);
			const int Color[4] = { 255, 255, 255, 255 };
			DrawScrText("Here text D3D_Present2", mBottomPos, 0.7f, 0, Color, false, true);
		}
	};

	class InputHandler1 : public GameEventHandlerProxy<IGameEventInput>, public ISingleton<InputHandler1>
	{
	public:
		using GameEventHandlerProxy<IGameEventInput>::GameEventHandlerProxy;
		Update1* getScriptContext() {
			return (Update1*)getProxy();
		}

		void keyUp(KEY keyCode) override
		{
			if (keyCode == KeyCode::Y)
			{
				getScriptContext()->off = true;
			}

			//check pools
			if (keyCode == KeyCode::O)
			{
				GamePool::Ped_t peds = GamePool::Ped();
				GamePool::Ped_t::iterator
					begin = peds.begin(),
					end = peds.end();
				size_t count1 = peds.getCount();
				size_t itemsize1 = peds.getItemSize();

				int count = 0;
				for (auto it : peds) {
					GameObject::Ped ped(&it);
					byte type = ped.getEntity().getType();
					
					if (type == 4) {
						int id = ped.getEntity().getFieldValue<int>(0x8);
						count++;
					}
				}

				GamePool::Vehicle_t vehicles = GamePool::Vehicle();
				size_t count2 = vehicles.getCount();
				size_t maxCount2 = vehicles.getMaxCount();

				return;

				count = 0;
				auto it = GamePool::Vehicle().begin();
				auto last = GamePool::Vehicle().end();
				for (; it != last; it++) {
					GameObject::Vehicle veh(&it);
					byte type = veh.getEntity().getType();
					count++;
				}

				count = 0;
				for (auto it : vehicles) {
					byte type = GameObject::Vehicle(&it).getEntity().getType();
					count++;
				}

				GamePool::Object_t objs = GamePool::Object();
			}

			//check natives
			else if (false)
			{
				GameScripts::getScriptByName("building_controller")->terminate();
				GameScripts::getScriptByName("vehicle_gen_controller")->terminate();
				set_status_text("~b~TERMINATE");
			}

			//GAME NATIVES
			if (false)
			{
				//check natives
				if (keyCode == KeyCode::F6)
				{
					Player player = PLAYER::PLAYER_ID();
					PLAYER::SET_PLAYER_CAN_USE_COVER(player, false);
					set_status_text("~b~YOU CANNOT HIDE NOW");
				}


				//remove car
				if (keyCode == KeyCode::F7)
				{
					SE::Ped playerPed = PLAYER::PLAYER_PED_ID();
					if (PED::IS_PED_IN_ANY_VEHICLE(playerPed, false))
					{
						int Vehicle = PED::GET_VEHICLE_PED_IS_USING(playerPed);
						VEHICLE::DELETE_VEHICLE(&Vehicle);
						set_status_text("~b~YOU REMOVE VEHICLE");
					}
				}



				//
				if (keyCode == KeyCode::H)
				{
					SE::Ped playerPed = PLAYER::PLAYER_PED_ID();
					if (PED::IS_PED_IN_ANY_VEHICLE(playerPed, false))
					{
						int Vehicle = PED::GET_VEHICLE_PED_IS_USING(playerPed);
						getScriptContext()->PaintVehRandom(Vehicle);
						set_status_text("~b~YOU REMOVE VEHICLE");
					}
				}

				
				if (keyCode == KeyCode::K)
				{
					auto pos = ENTITY::GET_ENTITY_COORDS(PLAYER::PLAYER_PED_ID(), 0);
					float heading = ENTITY::GET_ENTITY_HEADING(PLAYER::PLAYER_PED_ID());

					auto ped_ = PED::CREATE_RANDOM_PED(pos.x, pos.y, pos.z);

					auto ped = SDK::CREATE::PED_Random(pos);
					SDK::Vector3D pos2 = ped->getPos();
					SDK::Vector3D rot2 = ped->getRot();
					
				}

				if (keyCode == KeyCode::O)
				{
					using namespace SDK;
					auto pos = ENTITY::GET_ENTITY_COORDS(PLAYER::PLAYER_PED_ID(), 0);
					auto trevor = CREATE::PED_Test(pos);
					if (trevor != nullptr) {
						trevor->getWeapons()->give(HASH::Weapon::Minigun, 100, false, false);
						trevor->getWeapons()->give(HASH::Weapon::Grenade, 10);
						trevor->getWeapons()->select(HASH::Weapon::Minigun);

						trevor->playAnim(
							SDK::ANIM::weapons["projectile@"]
							.get("aimlive_m")
							.setConfig(SDK::ANIM::CFG_Standart)
						);
					}
				}
			}
			else {
				set_status_text("~r~ERROR: SCRIPT ENGINE NOT INIT YET");
			}
		}
	};
};


class InputHandler2 : public IGameEventInput
{
public:
	void keyUp(KEY keyCode) override
	{
		//показать курсор и не возвращать назад(поверх окна)
		if (keyCode == KeyCode::F2)
		{
			static bool retCursorBack = false;
			if (retCursorBack) retCursorBack = false; else retCursorBack = true;
			GameCursorPointer::setNotReturnBack(retCursorBack);
		}

		//просто показать курсор внутри игры
		else if (keyCode == KeyCode::F1)
		{
			static bool showCursor = false;
			if (showCursor) showCursor = false; else showCursor = true;
			GameCursorPointer::show(showCursor);
		}

		//выйти из игры
		else if (keyCode == KeyCode::F3)
		{
			GameExit::Exit();
		}

		//подгрузить dll
		else if (keyCode == KeyCode::F5)
		{
			HANDLE dll = LoadLibrary("SDA.dll");
			
		}
	}
};




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		Sleep(2000);
		
		GameScriptEngine::addEventHandler(
			new Update1
		);
		GameInput::addEventHandler(
			new InputHandler2
		);
		
		new GameAppInfo(hModule);
		new Core;
		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}