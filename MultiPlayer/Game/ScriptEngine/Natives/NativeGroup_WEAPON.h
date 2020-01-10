#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class WEAPON : public IGameNativeGroup<WEAPON>
	{
	public:
		static GameNative<void(BOOL toggle), 0xC8B46D7727D864AA> ENABLE_LASER_SIGHT_RENDERING;
		static GameNative<Hash(Hash componentHash), 0x0DB57B41EC1DB083> GET_WEAPON_COMPONENT_TYPE_MODEL;
		static GameNative<Hash(Hash weaponHash), 0xF46CDC33180FDA94> GET_WEAPONTYPE_MODEL;
		static GameNative<Hash(Hash weaponHash), 0x4215460B9B8B7FA0> GET_WEAPONTYPE_SLOT;
		static GameNative<Hash(Hash weaponHash), 0xC3287EE3050FB74C> GET_WEAPONTYPE_GROUP;
		static GameNative<void(Ped ped, Hash weaponHash, BOOL equipNow), 0xADF692B254977C0C> SET_CURRENT_PED_WEAPON;
		static GameNative<BOOL(Ped ped, Hash* weaponHash, BOOL unused), 0x3A87E44BB9A01D54> GET_CURRENT_PED_WEAPON;
		static GameNative<Entity(Ped ped), 0x3B390A939AF0B5FC> GET_CURRENT_PED_WEAPON_ENTITY_INDEX;
		static GameNative<Hash(Ped ped, BOOL p1), 0x8483E98E8B888AE2> GET_BEST_PED_WEAPON;
		static GameNative<BOOL(Ped ped, Hash weaponHash), 0x75C55983C2C39DAA> SET_CURRENT_PED_VEHICLE_WEAPON;
		static GameNative<BOOL(Ped ped, Hash* weaponHash), 0x1017582BCD3832DC> GET_CURRENT_PED_VEHICLE_WEAPON;
		static GameNative<BOOL(Ped ped, int p1), 0x475768A975D5AD17> IS_PED_ARMED;
		static GameNative<BOOL(Hash weaponHash), 0x937C71165CF334B3> IS_WEAPON_VALID;
		static GameNative<BOOL(Ped ped, Hash weaponHash, BOOL p2), 0x8DECB02F88F428BC> HAS_PED_GOT_WEAPON;
		static GameNative<BOOL(Ped ped), 0xB80CA294F2F26749> IS_PED_WEAPON_READY_TO_SHOOT;
		static GameNative<Hash(Ped ped, Hash weaponSlot), 0xEFFED78E9011134D> GET_PED_WEAPONTYPE_IN_SLOT;
		static GameNative<int(Ped ped, Hash weaponhash), 0x015A522136D7F951> GET_AMMO_IN_PED_WEAPON;
		static GameNative<void(Ped ped, Hash weaponHash, int ammo), 0x78F0424C34306220> ADD_AMMO_TO_PED;
		static GameNative<void(Ped ped, Hash weaponHash, int ammo), 0x14E56BC5B5DB6A19> SET_PED_AMMO;
		static GameNative<void(Ped ped, BOOL toggle, Hash weaponHash), 0x3EDCB0505123623B> SET_PED_INFINITE_AMMO;
		static GameNative<void(Ped ped, BOOL toggle), 0x183DADC6AA953186> SET_PED_INFINITE_AMMO_CLIP;
		static GameNative<void(Ped ped, Hash weaponHash, int ammoCount, BOOL isHidden, BOOL equipNow), 0xBF0FD6E56C964FCB> GIVE_WEAPON_TO_PED;
		static GameNative<void(Ped ped, Hash weaponHash, int ammoCount, BOOL equipNow), 0xB282DC6EBD803C75> GIVE_DELAYED_WEAPON_TO_PED;
		static GameNative<void(Ped ped, BOOL unused), 0xF25DF915FA38C5F3> REMOVE_ALL_PED_WEAPONS;
		static GameNative<void(Ped ped, Hash weaponHash), 0x4899CB088EDF59B8> REMOVE_WEAPON_FROM_PED;
		static GameNative<void(Ped ped, BOOL toggle), 0x6F6981D2253C208F> HIDE_PED_WEAPON_FOR_SCRIPTED_CUTSCENE;
		static GameNative<void(Ped ped, BOOL visible, BOOL deselectWeapon, BOOL p3, BOOL p4), 0x0725A4CCFDED9A70> SET_PED_CURRENT_WEAPON_VISIBLE;
		static GameNative<void(Ped ped, BOOL toggle), 0x476AE72C1D19D1A8> SET_PED_DROPS_WEAPONS_WHEN_DEAD;
		static GameNative<BOOL(Ped ped, Hash weaponHash, int weaponType), 0x2D343D2219CD027A> HAS_PED_BEEN_DAMAGED_BY_WEAPON;
		static GameNative<void(Ped ped), 0x0E98F88A24C5F4B8> CLEAR_PED_LAST_WEAPON_DAMAGE;
		static GameNative<BOOL(Entity entity, Hash weaponHash, int weaponType), 0x131D401334815E94> HAS_ENTITY_BEEN_DAMAGED_BY_WEAPON;
		static GameNative<void(Entity entity), 0xAC678E40BE7C74D2> CLEAR_ENTITY_LAST_WEAPON_DAMAGE;
		static GameNative<void(Ped ped), 0x6B7513D9966FBEC0> SET_PED_DROPS_WEAPON;
		static GameNative<void(Ped ped, Hash weaponHash, float xOffset, float yOffset, float zOffset, int ammoCount), 0x208A1888007FC0E6> SET_PED_DROPS_INVENTORY_WEAPON;
		static GameNative<int(Ped ped, Hash weaponHash, BOOL p2), 0xA38DCFFCEA8962FA> GET_MAX_AMMO_IN_CLIP;
		static GameNative<BOOL(Ped ped, Hash weaponHash, int* ammo), 0x2E1202248937775C> GET_AMMO_IN_CLIP;
		static GameNative<BOOL(Ped ped, Hash weaponHash, int ammo), 0xDCD2A934D65CB497> SET_AMMO_IN_CLIP;
		static GameNative<BOOL(Ped ped, Hash weaponHash, int* ammo), 0xDC16122C7A20C933> GET_MAX_AMMO;
		static GameNative<void(Ped ped, Hash ammoType, int ammo), 0x5FD1E1F011E76D7E> SET_PED_AMMO_BY_TYPE;
		static GameNative<int(Ped ped, Hash ammoType), 0x39D22031557946C1> GET_PED_AMMO_BY_TYPE;
		static GameNative<void(Any ammoType, int ammo), 0xA4EFEF9440A5B0EF> SET_PED_AMMO_TO_DROP;
		static GameNative<void(float p0), 0xE620FD3512A04F18> _0xE620FD3512A04F18;
		static GameNative<Hash(Ped ped, Hash weaponHash), 0x7FEAD38B326B9F74> GET_PED_AMMO_TYPE_FROM_WEAPON;
		static GameNative<BOOL(Ped ped, Vector3* coords), 0x6C4D0409BA1A2BC2> GET_PED_LAST_WEAPON_IMPACT_COORD;
		static GameNative<void(Ped ped, Hash gadgetHash, BOOL p2), 0xD0D7B1E680ED4A1A> SET_PED_GADGET;
		static GameNative<BOOL(Ped ped, Hash gadgetHash), 0xF731332072F5156C> GET_IS_PED_GADGET_EQUIPPED;
		static GameNative<Hash(Ped ped), 0x0A6DB4965674D243> GET_SELECTED_PED_WEAPON;
		static GameNative<void(Ped ped, Hash weaponHash, BOOL p2), 0xFC4BD125DE7611E4> EXPLODE_PROJECTILES;
		static GameNative<void(Hash weaponHash, BOOL p1), 0xFC52E0F37E446528> REMOVE_ALL_PROJECTILES_OF_TYPE;
		static GameNative<float(Ped ped), 0x840F03E9041E2C9C> _GET_LOCKON_RANGE_OF_CURRENT_PED_WEAPON;
		static GameNative<float(Ped ped), 0x814C9D19DFD69679> GET_MAX_RANGE_OF_CURRENT_PED_WEAPON;
		static GameNative<BOOL(Ped driver, Vehicle vehicle, Hash weaponHash, Any p3), 0x717C8481234E3B88> HAS_VEHICLE_GOT_PROJECTILE_ATTACHED;
		static GameNative<void(Ped ped, Hash weaponHash, Hash componentHash), 0xD966D51AA5B28BB9> GIVE_WEAPON_COMPONENT_TO_PED;
		static GameNative<void(Ped ped, Hash weaponHash, Hash componentHash), 0x1E8BE90C74FB4C09> REMOVE_WEAPON_COMPONENT_FROM_PED;
		static GameNative<BOOL(Ped ped, Hash weaponHash, Hash componentHash), 0xC593212475FAE340> HAS_PED_GOT_WEAPON_COMPONENT;
		static GameNative<BOOL(Ped ped, Hash weaponHash, Hash componentHash), 0x0D78DE0572D3969E> IS_PED_WEAPON_COMPONENT_ACTIVE;
		static GameNative<BOOL(Ped ped), 0x8C0D57EA686FAD87> _PED_SKIP_NEXT_RELOADING;
		static GameNative<BOOL(Ped ped), 0x20AE33F3AC9C0033> MAKE_PED_RELOAD;
		static GameNative<void(Hash weaponHash, int p1, int p2), 0x5443438F033E29C3> REQUEST_WEAPON_ASSET;
		static GameNative<BOOL(Hash weaponHash), 0x36E353271F0E90EE> HAS_WEAPON_ASSET_LOADED;
		static GameNative<void(Hash weaponHash), 0xAA08EF13F341C8FC> REMOVE_WEAPON_ASSET;
		static GameNative<Object(Hash weaponHash, int ammoCount, float x, float y, float z, BOOL showWorldModel, float heading, Any p7), 0x9541D3CF0D398F36> CREATE_WEAPON_OBJECT;
		static GameNative<void(Object weaponObject, Hash addonHash), 0x33E179436C0B31DB> GIVE_WEAPON_COMPONENT_TO_WEAPON_OBJECT;
		static GameNative<void(Object weaponObject, Hash component), 0xF7D82B0D66777611> REMOVE_WEAPON_COMPONENT_FROM_WEAPON_OBJECT;
		static GameNative<BOOL(Object weapon, Hash addonHash), 0x76A18844E743BF91> HAS_WEAPON_GOT_WEAPON_COMPONENT;
		static GameNative<void(Object weaponObject, Ped ped), 0xB1FA61371AF7C4B7> GIVE_WEAPON_OBJECT_TO_PED;
		static GameNative<BOOL(Hash weaponHash, Hash componentHash), 0x5CEE3DF569CECAB0> DOES_WEAPON_TAKE_WEAPON_COMPONENT;
		static GameNative<Object(Ped ped, BOOL p1), 0xCAE1DC9A0E22A16D> GET_WEAPON_OBJECT_FROM_PED;
		static GameNative<void(Ped ped, Hash weaponHash, int tintIndex), 0x50969B9B89ED5738> SET_PED_WEAPON_TINT_INDEX;
		static GameNative<int(Ped ped, Hash weaponHash), 0x2B9EEDC07BD06B9F> GET_PED_WEAPON_TINT_INDEX;
		static GameNative<void(Object weapon, int tintIndex), 0xF827589017D4E4A9> SET_WEAPON_OBJECT_TINT_INDEX;
		static GameNative<int(Object weapon), 0xCD183314F7CD2E57> GET_WEAPON_OBJECT_TINT_INDEX;
		static GameNative<int(Hash weaponHash), 0x5DCF6C5CAB2E9BF7> GET_WEAPON_TINT_COUNT;
		static GameNative<BOOL(Hash weaponHash, Any* outData), 0xD92C739EE34C9EBA> GET_WEAPON_HUD_STATS;
		static GameNative<BOOL(Hash componentHash, int* outData), 0xB3CAF387AE12E9F8> GET_WEAPON_COMPONENT_HUD_STATS;
		static GameNative<float(Hash weapon, int p1), 0x3133B907D8B32053> _0x3133B907D8B32053;
		static GameNative<int(Hash weaponHash), 0x583BE370B1EC6EB4> GET_WEAPON_CLIP_SIZE;
		static GameNative<void(Ped ped, float xBias, float yBias), 0x8378627201D5497D> SET_PED_CHANCE_OF_FIRING_BLANKS;
		static GameNative<Entity(Ped ped, BOOL p1), 0xB4C8D77C80C0421E> _0xB4C8D77C80C0421E;
		static GameNative<void(Entity weaponObject), 0x48164DBB970AC3F0> REQUEST_WEAPON_HIGH_DETAIL_MODEL;
		static GameNative<BOOL(Ped ped), 0x65F0C5AE05943EC7> IS_PED_CURRENT_WEAPON_SILENCED;
		static GameNative<BOOL(Ped ped), 0x4B7620C47217126C> SET_WEAPON_SMOKEGRENADE_ASSIGNED;
		static GameNative<Any(float distance), 0xCEA66DAD478CD39B> SET_FLASH_LIGHT_FADE_DISTANCE;
		static GameNative<void(Ped ped, Hash animStyle), 0x1055AC3A667F09D9> SET_WEAPON_ANIMATION_OVERRIDE;
		static GameNative<int(Hash weaponHash), 0x3BE0BB12D25FB305> GET_WEAPON_DAMAGE_TYPE;
		static GameNative<void(Ped ped), 0xE4DCEC7FD5B739A5> _0xE4DCEC7FD5B739A5;
		static GameNative<BOOL(Hash weaponHash), 0xBC7BE5ABC0879F74> CAN_USE_WEAPON_ON_PARACHUTE;
	};
};