#include "NativeGroup_OBJECT.h"



//Native init
#define NATIVE(name) GAME_NATIVE_INIT(OBJECT, ##name)

using namespace SE;

//Natives
NATIVE(CREATE_OBJECT)
NATIVE(CREATE_OBJECT_NO_OFFSET)
NATIVE(DELETE_OBJECT)
NATIVE(PLACE_OBJECT_ON_GROUND_PROPERLY)
NATIVE(SLIDE_OBJECT)
NATIVE(SET_OBJECT_TARGETTABLE)
NATIVE(_SET_OBJECT_LOD)
NATIVE(GET_CLOSEST_OBJECT_OF_TYPE)
NATIVE(HAS_OBJECT_BEEN_BROKEN)
NATIVE(HAS_CLOSEST_OBJECT_OF_TYPE_BEEN_BROKEN)
NATIVE(_0x46494A2475701343)
NATIVE(_GET_OBJECT_OFFSET_FROM_COORDS)
NATIVE(_0x163F8B586BC95F2A)
NATIVE(SET_STATE_OF_CLOSEST_DOOR_OF_TYPE)
NATIVE(GET_STATE_OF_CLOSEST_DOOR_OF_TYPE)
NATIVE(_DOOR_CONTROL)
NATIVE(ADD_DOOR_TO_SYSTEM)
NATIVE(REMOVE_DOOR_FROM_SYSTEM)
NATIVE(_SET_DOOR_ACCELERATION_LIMIT)
NATIVE(_0x160AA1B32F6139B8)
NATIVE(_0x4BC2854478F3A749)
NATIVE(_0x03C27E13B42A0E82)
NATIVE(_0x9BA001CB45CBF627)
NATIVE(_SET_DOOR_AJAR_ANGLE)
NATIVE(_0x65499865FCA6E5EC)
NATIVE(_0xC485E07E4F0B7958)
NATIVE(_0xD9B71952F78A2640)
NATIVE(_0xA85A21582451E951)
NATIVE(_DOES_DOOR_EXIST)
NATIVE(IS_DOOR_CLOSED)
NATIVE(_0xC7F29CA00F46350E)
NATIVE(_0x701FDA1E82076BA4)
NATIVE(_0xDF97CDD4FC08FD34)
NATIVE(_0x589F80B325CC82C5)
NATIVE(IS_GARAGE_EMPTY)
NATIVE(_0x024A60DEB0EA69F0)
NATIVE(_0x1761DC5D8471CBAA)
NATIVE(_0x85B6C850546FDDE2)
NATIVE(_0x673ED815D6E323B7)
NATIVE(_0x372EF6699146A1E4)
NATIVE(_0xF0EED5A6BC7B237A)
NATIVE(_0x190428512B240692)
NATIVE(_0xF2E1A7133DD356A6)
NATIVE(_0x66A49D021870FE88)
NATIVE(DOES_OBJECT_OF_TYPE_EXIST_AT_COORDS)
NATIVE(IS_POINT_IN_ANGLED_AREA)
NATIVE(_0x4D89D607CB3DD1D2)
NATIVE(SET_OBJECT_PHYSICS_PARAMS)
NATIVE(GET_OBJECT_FRAGMENT_DAMAGE_HEALTH)
NATIVE(SET_ACTIVATE_OBJECT_PHYSICS_AS_SOON_AS_IT_IS_UNFROZEN)
NATIVE(IS_ANY_OBJECT_NEAR_POINT)
NATIVE(IS_OBJECT_NEAR_POINT)
NATIVE(_0x4A39DB43E47CF3AA)
NATIVE(_0xE7E4C198B0185900)
NATIVE(_0xF9C1681347C8BD15)
NATIVE(TRACK_OBJECT_VISIBILITY)
NATIVE(IS_OBJECT_VISIBLE)
NATIVE(_0xC6033D32241F6FB5)
NATIVE(_0xEB6F1A9B5510A5D2)
NATIVE(_0xBCE595371A5FBAAF)
NATIVE(_GET_DES_OBJECT)
NATIVE(_SET_DES_OBJECT_STATE)
NATIVE(_GET_DES_OBJECT_STATE)
NATIVE(_DOES_DES_OBJECT_EXIST)
NATIVE(_0x260EE4FDBDF4DB01)
NATIVE(CREATE_PICKUP)
NATIVE(CREATE_PICKUP_ROTATE)
NATIVE(CREATE_AMBIENT_PICKUP)
NATIVE(CREATE_PORTABLE_PICKUP)
NATIVE(_CREATE_PORTABLE_PICKUP_2)
NATIVE(ATTACH_PORTABLE_PICKUP_TO_PED)
NATIVE(DETACH_PORTABLE_PICKUP_FROM_PED)
NATIVE(_0x0BF3B3BD47D79C08)
NATIVE(_0x78857FC65CADB909)
NATIVE(GET_SAFE_PICKUP_COORDS)
NATIVE(GET_PICKUP_COORDS)
NATIVE(REMOVE_ALL_PICKUPS_OF_TYPE)
NATIVE(HAS_PICKUP_BEEN_COLLECTED)
NATIVE(REMOVE_PICKUP)
NATIVE(CREATE_MONEY_PICKUPS)
NATIVE(DOES_PICKUP_EXIST)
NATIVE(DOES_PICKUP_OBJECT_EXIST)
NATIVE(GET_PICKUP_OBJECT)
NATIVE(_0x0378C08504160D0D)
NATIVE(_IS_PICKUP_WITHIN_RADIUS)
NATIVE(SET_PICKUP_REGENERATION_TIME)
NATIVE(_0x616093EC6B139DD9)
NATIVE(_0x88EAEC617CD26926)
NATIVE(SET_TEAM_PICKUP_OBJECT)
NATIVE(_0x92AEFB5F6E294023)
NATIVE(_0xA08FE5E49BDC39DD)
NATIVE(_0xDB41D07A45A6D4B7)
NATIVE(_0x318516E02DE3ECE2)
NATIVE(_0x31F924B53EADDF65)
NATIVE(_0xF92099527DB8E2A7)
NATIVE(_0xA2C1F5E92AFE49ED)
NATIVE(_0x762DB2D380B48D04)
NATIVE(_HIGHLIGHT_PLACEMENT_COORDS)
NATIVE(_0xB2D0BDE54F0E8E5A)
NATIVE(_GET_WEAPON_HASH_FROM_PICKUP)
NATIVE(_0x11D1E53A726891FE)
NATIVE(_SET_OBJECT_TEXTURE_VARIANT)
NATIVE(_GET_PICKUP_HASH)
NATIVE(SET_FORCE_OBJECT_THIS_FRAME)
NATIVE(_MARK_OBJECT_FOR_DELETION)

//Native list
STATIC_FIELD_INIT(IGameNativeGroup<OBJECT>::m_natives)
{
	&OBJECT::CREATE_OBJECT,
	&OBJECT::CREATE_OBJECT_NO_OFFSET,
	&OBJECT::DELETE_OBJECT,
	&OBJECT::PLACE_OBJECT_ON_GROUND_PROPERLY,
	&OBJECT::SLIDE_OBJECT,
	&OBJECT::SET_OBJECT_TARGETTABLE,
	&OBJECT::_SET_OBJECT_LOD,
	&OBJECT::GET_CLOSEST_OBJECT_OF_TYPE,
	&OBJECT::HAS_OBJECT_BEEN_BROKEN,
	&OBJECT::HAS_CLOSEST_OBJECT_OF_TYPE_BEEN_BROKEN,
	&OBJECT::_0x46494A2475701343,
	&OBJECT::_GET_OBJECT_OFFSET_FROM_COORDS,
	&OBJECT::_0x163F8B586BC95F2A,
	&OBJECT::SET_STATE_OF_CLOSEST_DOOR_OF_TYPE,
	&OBJECT::GET_STATE_OF_CLOSEST_DOOR_OF_TYPE,
	&OBJECT::_DOOR_CONTROL,
	&OBJECT::ADD_DOOR_TO_SYSTEM,
	&OBJECT::REMOVE_DOOR_FROM_SYSTEM,
	&OBJECT::_SET_DOOR_ACCELERATION_LIMIT,
	&OBJECT::_0x160AA1B32F6139B8,
	&OBJECT::_0x4BC2854478F3A749,
	&OBJECT::_0x03C27E13B42A0E82,
	&OBJECT::_0x9BA001CB45CBF627,
	&OBJECT::_SET_DOOR_AJAR_ANGLE,
	&OBJECT::_0x65499865FCA6E5EC,
	&OBJECT::_0xC485E07E4F0B7958,
	&OBJECT::_0xD9B71952F78A2640,
	&OBJECT::_0xA85A21582451E951,
	&OBJECT::_DOES_DOOR_EXIST,
	&OBJECT::IS_DOOR_CLOSED,
	&OBJECT::_0xC7F29CA00F46350E,
	&OBJECT::_0x701FDA1E82076BA4,
	&OBJECT::_0xDF97CDD4FC08FD34,
	&OBJECT::_0x589F80B325CC82C5,
	&OBJECT::IS_GARAGE_EMPTY,
	&OBJECT::_0x024A60DEB0EA69F0,
	&OBJECT::_0x1761DC5D8471CBAA,
	&OBJECT::_0x85B6C850546FDDE2,
	&OBJECT::_0x673ED815D6E323B7,
	&OBJECT::_0x372EF6699146A1E4,
	&OBJECT::_0xF0EED5A6BC7B237A,
	&OBJECT::_0x190428512B240692,
	&OBJECT::_0xF2E1A7133DD356A6,
	&OBJECT::_0x66A49D021870FE88,
	&OBJECT::DOES_OBJECT_OF_TYPE_EXIST_AT_COORDS,
	&OBJECT::IS_POINT_IN_ANGLED_AREA,
	&OBJECT::_0x4D89D607CB3DD1D2,
	&OBJECT::SET_OBJECT_PHYSICS_PARAMS,
	&OBJECT::GET_OBJECT_FRAGMENT_DAMAGE_HEALTH,
	&OBJECT::SET_ACTIVATE_OBJECT_PHYSICS_AS_SOON_AS_IT_IS_UNFROZEN,
	&OBJECT::IS_ANY_OBJECT_NEAR_POINT,
	&OBJECT::IS_OBJECT_NEAR_POINT,
	&OBJECT::_0x4A39DB43E47CF3AA,
	&OBJECT::_0xE7E4C198B0185900,
	&OBJECT::_0xF9C1681347C8BD15,
	&OBJECT::TRACK_OBJECT_VISIBILITY,
	&OBJECT::IS_OBJECT_VISIBLE,
	&OBJECT::_0xC6033D32241F6FB5,
	&OBJECT::_0xEB6F1A9B5510A5D2,
	&OBJECT::_0xBCE595371A5FBAAF,
	&OBJECT::_GET_DES_OBJECT,
	&OBJECT::_SET_DES_OBJECT_STATE,
	&OBJECT::_GET_DES_OBJECT_STATE,
	&OBJECT::_DOES_DES_OBJECT_EXIST,
	&OBJECT::_0x260EE4FDBDF4DB01,
	&OBJECT::CREATE_PICKUP,
	&OBJECT::CREATE_PICKUP_ROTATE,
	&OBJECT::CREATE_AMBIENT_PICKUP,
	&OBJECT::CREATE_PORTABLE_PICKUP,
	&OBJECT::_CREATE_PORTABLE_PICKUP_2,
	&OBJECT::ATTACH_PORTABLE_PICKUP_TO_PED,
	&OBJECT::DETACH_PORTABLE_PICKUP_FROM_PED,
	&OBJECT::_0x0BF3B3BD47D79C08,
	&OBJECT::_0x78857FC65CADB909,
	&OBJECT::GET_SAFE_PICKUP_COORDS,
	&OBJECT::GET_PICKUP_COORDS,
	&OBJECT::REMOVE_ALL_PICKUPS_OF_TYPE,
	&OBJECT::HAS_PICKUP_BEEN_COLLECTED,
	&OBJECT::REMOVE_PICKUP,
	&OBJECT::CREATE_MONEY_PICKUPS,
	&OBJECT::DOES_PICKUP_EXIST,
	&OBJECT::DOES_PICKUP_OBJECT_EXIST,
	&OBJECT::GET_PICKUP_OBJECT,
	&OBJECT::_0x0378C08504160D0D,
	&OBJECT::_IS_PICKUP_WITHIN_RADIUS,
	&OBJECT::SET_PICKUP_REGENERATION_TIME,
	&OBJECT::_0x616093EC6B139DD9,
	&OBJECT::_0x88EAEC617CD26926,
	&OBJECT::SET_TEAM_PICKUP_OBJECT,
	&OBJECT::_0x92AEFB5F6E294023,
	&OBJECT::_0xA08FE5E49BDC39DD,
	&OBJECT::_0xDB41D07A45A6D4B7,
	&OBJECT::_0x318516E02DE3ECE2,
	&OBJECT::_0x31F924B53EADDF65,
	&OBJECT::_0xF92099527DB8E2A7,
	&OBJECT::_0xA2C1F5E92AFE49ED,
	&OBJECT::_0x762DB2D380B48D04,
	&OBJECT::_HIGHLIGHT_PLACEMENT_COORDS,
	&OBJECT::_0xB2D0BDE54F0E8E5A,
	&OBJECT::_GET_WEAPON_HASH_FROM_PICKUP,
	&OBJECT::_0x11D1E53A726891FE,
	&OBJECT::_SET_OBJECT_TEXTURE_VARIANT,
	&OBJECT::_GET_PICKUP_HASH,
	&OBJECT::SET_FORCE_OBJECT_THIS_FRAME,
	&OBJECT::_MARK_OBJECT_FOR_DELETION,
};