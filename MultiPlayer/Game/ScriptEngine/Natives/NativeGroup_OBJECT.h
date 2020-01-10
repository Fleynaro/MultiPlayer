#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class OBJECT : public IGameNativeGroup<OBJECT>
	{
	public:
		static GameNative<Object(Object modelHash, float x, float y, float z, BOOL isNetwork, BOOL thisScriptCheck, BOOL dynamic), 0x509D5878EB39E842> CREATE_OBJECT;
		static GameNative<float(int* modelfwgaHash, float x, float y, float z, BOOL isNetwork, BOOL thisScriptCheck, BOOL dynamic), 0x9A294B2138ABB884> CREATE_OBJECT_NO_OFFSET;
		static GameNative<void(Object* object), 0x539E0AE3E6634B9F> DELETE_OBJECT;
		static GameNative<BOOL(Object object), 0x58A850EAEE20FAA3> PLACE_OBJECT_ON_GROUND_PROPERLY;
		static GameNative<BOOL(Object object, float toX, float toY, float toZ, float speedX, float speedY, float speedZ, BOOL collision), 0x2FDFF4107B8C1147> SLIDE_OBJECT;
		static GameNative<void(Object object, BOOL targettable), 0x8A7391690F5AFD81> SET_OBJECT_TARGETTABLE;
		static GameNative<void(Object object, BOOL toggle), 0x77F33F2CCF64B3AA> _SET_OBJECT_LOD;
		static GameNative<Object(float x, float y, float z, float radius, Hash modelHash, BOOL isMission, BOOL p6, BOOL p7), 0xE143FA2249364369> GET_CLOSEST_OBJECT_OF_TYPE;
		static GameNative<BOOL(Object object), 0x8ABFB70C49CC43E2> HAS_OBJECT_BEEN_BROKEN;
		static GameNative<BOOL(float p0, float p1, float p2, float p3, Hash modelHash, Any p5), 0x761B0E69AC4D007E> HAS_CLOSEST_OBJECT_OF_TYPE_BEEN_BROKEN;
		static GameNative<BOOL(float p0, float p1, float p2, float p3, Hash modelHash, BOOL p5), 0x46494A2475701343> _0x46494A2475701343;
		static GameNative<Vector3(float xPos, float yPos, float zPos, float heading, float xOffset, float yOffset, float zOffset), 0x163E252DE035A133> _GET_OBJECT_OFFSET_FROM_COORDS;
		static GameNative<Any(Any coords, float radius, Hash modelHash, float x, float y, float z, Vector3* p6, int p7), 0x163F8B586BC95F2A> _0x163F8B586BC95F2A;
		static GameNative<void(Hash type, float x, float y, float z, BOOL locked, float heading, BOOL p6), 0xF82D8F1926A02C3D> SET_STATE_OF_CLOSEST_DOOR_OF_TYPE;
		static GameNative<void(Hash type, float x, float y, float z, BOOL* locked, float* heading), 0xEDC1A5B84AEF33FF> GET_STATE_OF_CLOSEST_DOOR_OF_TYPE;
		static GameNative<void(Hash doorHash, float x, float y, float z, BOOL locked, float xRotMult, float yRotMult, float zRotMult), 0x9B12F9A24FABEDB0> _DOOR_CONTROL;
		static GameNative<void(Hash doorHash, Hash modelHash, float x, float y, float z, BOOL p5, BOOL p6, BOOL p7), 0x6F8838D03D1DC226> ADD_DOOR_TO_SYSTEM;
		static GameNative<void(Hash doorHash), 0x464D8E1427156FE4> REMOVE_DOOR_FROM_SYSTEM;
		static GameNative<void(Hash doorHash, int limit, BOOL p2, BOOL p3), 0x6BAB9442830C7F53> _SET_DOOR_ACCELERATION_LIMIT;
		static GameNative<int(Hash doorHash), 0x160AA1B32F6139B8> _0x160AA1B32F6139B8;
		static GameNative<int(Hash doorHash), 0x4BC2854478F3A749> _0x4BC2854478F3A749;
		static GameNative<void(Hash doorHash, float p1, BOOL p2, BOOL p3), 0x03C27E13B42A0E82> _0x03C27E13B42A0E82;
		static GameNative<void(Hash doorHash, float heading, BOOL p2, BOOL p3), 0x9BA001CB45CBF627> _0x9BA001CB45CBF627;
		static GameNative<void(Hash doorHash, float ajar, BOOL p2, BOOL p3), 0xB6E6FBA95C7324AC> _SET_DOOR_AJAR_ANGLE;
		static GameNative<float(Hash doorHash), 0x65499865FCA6E5EC> _0x65499865FCA6E5EC;
		static GameNative<void(Hash doorHash, BOOL p1, BOOL p2, BOOL p3), 0xC485E07E4F0B7958> _0xC485E07E4F0B7958;
		static GameNative<void(Hash doorHash, BOOL p1), 0xD9B71952F78A2640> _0xD9B71952F78A2640;
		static GameNative<void(Hash doorHash, BOOL p1), 0xA85A21582451E951> _0xA85A21582451E951;
		static GameNative<BOOL(Hash doorHash), 0xC153C43EA202C8C1> _DOES_DOOR_EXIST;
		static GameNative<BOOL(Hash door), 0xC531EE8A1145A149> IS_DOOR_CLOSED;
		static GameNative<void(BOOL p0), 0xC7F29CA00F46350E> _0xC7F29CA00F46350E;
		static GameNative<void(), 0x701FDA1E82076BA4> _0x701FDA1E82076BA4;
		static GameNative<BOOL(Any p0), 0xDF97CDD4FC08FD34> _0xDF97CDD4FC08FD34;
		static GameNative<BOOL(float p0, float p1, float p2, Any p3, Any* p4), 0x589F80B325CC82C5> _0x589F80B325CC82C5;
		static GameNative<BOOL(Any garage, BOOL p1, int p2), 0x90E47239EA1980B8> IS_GARAGE_EMPTY;
		static GameNative<BOOL(Any p0, Player player, float p2, int p3), 0x024A60DEB0EA69F0> _0x024A60DEB0EA69F0;
		static GameNative<BOOL(Any p0, Player player, int p2), 0x1761DC5D8471CBAA> _0x1761DC5D8471CBAA;
		static GameNative<BOOL(Any p0, BOOL p1, BOOL p2, BOOL p3, Any p4), 0x85B6C850546FDDE2> _0x85B6C850546FDDE2;
		static GameNative<BOOL(Any p0, BOOL p1, BOOL p2, BOOL p3, Any p4), 0x673ED815D6E323B7> _0x673ED815D6E323B7;
		static GameNative<BOOL(Any p0, Entity entity, float p2, int p3), 0x372EF6699146A1E4> _0x372EF6699146A1E4;
		static GameNative<BOOL(Any p0, Entity entity, int p2), 0xF0EED5A6BC7B237A> _0xF0EED5A6BC7B237A;
		static GameNative<void(Any p0, BOOL p1, BOOL p2, BOOL p3, BOOL p4), 0x190428512B240692> _0x190428512B240692;
		static GameNative<void(Hash hash, BOOL toggle), 0xF2E1A7133DD356A6> _0xF2E1A7133DD356A6;
		static GameNative<void(), 0x66A49D021870FE88> _0x66A49D021870FE88;
		static GameNative<BOOL(float x, float y, float z, float radius, Hash hash, BOOL p5), 0xBFA48E2FF417213F> DOES_OBJECT_OF_TYPE_EXIST_AT_COORDS;
		static GameNative<BOOL(float p0, float p1, float p2, float p3, float p4, float p5, float p6, float p7, float p8, float p9, BOOL p10, BOOL p11), 0x2A70BAE8883E4C81> IS_POINT_IN_ANGLED_AREA;
		static GameNative<void(Object object, BOOL toggle), 0x4D89D607CB3DD1D2> _0x4D89D607CB3DD1D2;
		static GameNative<void(Object object, float mass, float gravityFactor, float dampingLinearC, float dampingLinearV, float dampingLinearV2, float dampingAngularC, float dampingAngularV, float dampingAngularV2, float margin, float default2Pi, float buoyancyFactor), 0xF6DF6E90DE7DF90F> SET_OBJECT_PHYSICS_PARAMS;
		static GameNative<float(Any p0, BOOL p1), 0xB6FBFD079B8D0596> GET_OBJECT_FRAGMENT_DAMAGE_HEALTH;
		static GameNative<void(Object object, BOOL toggle), 0x406137F8EF90EAF5> SET_ACTIVATE_OBJECT_PHYSICS_AS_SOON_AS_IT_IS_UNFROZEN;
		static GameNative<BOOL(float x, float y, float z, float range, BOOL p4), 0x397DC58FF00298D1> IS_ANY_OBJECT_NEAR_POINT;
		static GameNative<BOOL(Hash objectHash, float x, float y, float z, float range), 0x8C90FE4B381BA60A> IS_OBJECT_NEAR_POINT;
		static GameNative<void(Any p0), 0x4A39DB43E47CF3AA> _0x4A39DB43E47CF3AA;
		static GameNative<void(Object p0, Any p1, BOOL p2), 0xE7E4C198B0185900> _0xE7E4C198B0185900;
		static GameNative<void(Object object), 0xF9C1681347C8BD15> _0xF9C1681347C8BD15;
		static GameNative<void(Any p0), 0xB252BC036B525623> TRACK_OBJECT_VISIBILITY;
		static GameNative<BOOL(Object object), 0x8B32ACE6326A7546> IS_OBJECT_VISIBLE;
		static GameNative<void(Any p0, BOOL p1), 0xC6033D32241F6FB5> _0xC6033D32241F6FB5;
		static GameNative<void(Any p0, BOOL p1), 0xEB6F1A9B5510A5D2> _0xEB6F1A9B5510A5D2;
		static GameNative<void(Any p0, BOOL p1), 0xBCE595371A5FBAAF> _0xBCE595371A5FBAAF;
		static GameNative<int(float x, float y, float z, float rotation, char* name), 0xB48FCED898292E52> _GET_DES_OBJECT;
		static GameNative<void(int handle, int state), 0x5C29F698D404C5E1> _SET_DES_OBJECT_STATE;
		static GameNative<Any(int handle), 0x899BA936634A322E> _GET_DES_OBJECT_STATE;
		static GameNative<BOOL(int handle), 0x52AF537A0C5B8AAD> _DOES_DES_OBJECT_EXIST;
		static GameNative<float(Any p0), 0x260EE4FDBDF4DB01> _0x260EE4FDBDF4DB01;
		static GameNative<Pickup(Hash pickupHash, float posX, float posY, float posZ, int p4, int value, BOOL p6, Hash modelHash), 0xFBA08C503DD5FA58> CREATE_PICKUP;
		static GameNative<Pickup(Hash pickupHash, float posX, float posY, float posZ, float rotX, float rotY, float rotZ, int flag, int amount, Any p9, BOOL p10, Hash modelHash), 0x891804727E0A98B7> CREATE_PICKUP_ROTATE;
		static GameNative<Pickup(Hash pickupHash, float posX, float posY, float posZ, int flag, int value, Hash modelHash, BOOL returnHandle, BOOL p8), 0x673966A0C0FD7171> CREATE_AMBIENT_PICKUP;
		static GameNative<Pickup(Hash pickupHash, float x, float y, float z, BOOL placeOnGround, Hash modelHash), 0x2EAF1FDB2FB55698> CREATE_PORTABLE_PICKUP;
		static GameNative<Pickup(Hash pickupHash, float x, float y, float z, BOOL placeOnGround, Hash modelHash), 0x125494B98A21AAF7> _CREATE_PORTABLE_PICKUP_2;
		static GameNative<void(Ped ped, Any p1), 0x8DC39368BDD57755> ATTACH_PORTABLE_PICKUP_TO_PED;
		static GameNative<void(Ped ped), 0xCF463D1E9A0AECB1> DETACH_PORTABLE_PICKUP_FROM_PED;
		static GameNative<void(Hash hash, int p1), 0x0BF3B3BD47D79C08> _0x0BF3B3BD47D79C08;
		static GameNative<void(BOOL p0), 0x78857FC65CADB909> _0x78857FC65CADB909;
		static GameNative<Vector3(float x, float y, float z, Any p3, Any p4), 0x6E16BC2503FF1FF0> GET_SAFE_PICKUP_COORDS;
		static GameNative<Vector3(Pickup pickup), 0x225B8B35C88029B3> GET_PICKUP_COORDS;
		static GameNative<void(Hash pickupHash), 0x27F9D613092159CF> REMOVE_ALL_PICKUPS_OF_TYPE;
		static GameNative<BOOL(Pickup pickup), 0x80EC48E6679313F9> HAS_PICKUP_BEEN_COLLECTED;
		static GameNative<void(Pickup pickup), 0x3288D8ACAECD2AB2> REMOVE_PICKUP;
		static GameNative<void(float x, float y, float z, int value, int amount, Hash model), 0x0589B5E791CE9B2B> CREATE_MONEY_PICKUPS;
		static GameNative<BOOL(Pickup pickup), 0xAFC1CA75AD4074D1> DOES_PICKUP_EXIST;
		static GameNative<BOOL(Object pickupObject), 0xD9EFB6DBF7DAAEA3> DOES_PICKUP_OBJECT_EXIST;
		static GameNative<Object(Pickup pickup), 0x5099BC55630B25AE> GET_PICKUP_OBJECT;
		static GameNative<BOOL(Any p0), 0x0378C08504160D0D> _0x0378C08504160D0D;
		static GameNative<BOOL(Hash pickupHash, float x, float y, float z, float radius), 0xF9C36251F6E48E33> _IS_PICKUP_WITHIN_RADIUS;
		static GameNative<void(Pickup pickup, int duration), 0x78015C9B4B3ECC9D> SET_PICKUP_REGENERATION_TIME;
		static GameNative<void(Player player, Hash pickupHash, BOOL p2), 0x616093EC6B139DD9> _0x616093EC6B139DD9;
		static GameNative<void(Hash p0, BOOL p1), 0x88EAEC617CD26926> _0x88EAEC617CD26926;
		static GameNative<void(Object object, Any p1, BOOL p2), 0x53E0DF1A2A3CF0CA> SET_TEAM_PICKUP_OBJECT;
		static GameNative<void(Object object, BOOL p1, BOOL p2), 0x92AEFB5F6E294023> _0x92AEFB5F6E294023;
		static GameNative<void(Any p0, float p1, BOOL p2), 0xA08FE5E49BDC39DD> _0xA08FE5E49BDC39DD;
		static GameNative<int* (Hash pickupHash), 0xDB41D07A45A6D4B7> _0xDB41D07A45A6D4B7;
		static GameNative<void(float p0), 0x318516E02DE3ECE2> _0x318516E02DE3ECE2;
		static GameNative<void(BOOL p0), 0x31F924B53EADDF65> _0x31F924B53EADDF65;
		static GameNative<void(Any p0, Any p1), 0xF92099527DB8E2A7> _0xF92099527DB8E2A7;
		static GameNative<void(), 0xA2C1F5E92AFE49ED> _0xA2C1F5E92AFE49ED;
		static GameNative<void(Any p0), 0x762DB2D380B48D04> _0x762DB2D380B48D04;
		static GameNative<void(float x, float y, float z, int colorIndex), 0x3430676B11CDF21D> _HIGHLIGHT_PLACEMENT_COORDS;
		static GameNative<void(Object object, BOOL toggle), 0xB2D0BDE54F0E8E5A> _0xB2D0BDE54F0E8E5A;
		static GameNative<Hash(Pickup pickupHash), 0x08F96CA6C551AD51> _GET_WEAPON_HASH_FROM_PICKUP;
		static GameNative<BOOL(Object object), 0x11D1E53A726891FE> _0x11D1E53A726891FE;
		static GameNative<void(Object object, int paintIndex), 0x971DA0055324D033> _SET_OBJECT_TEXTURE_VARIANT;
		static GameNative<Hash(Pickup pickupHash), 0x5EAAD83F8CFB4575> _GET_PICKUP_HASH;
		static GameNative<void(Any p0, Any p1, Any p2, Any p3), 0xF538081986E49E9D> SET_FORCE_OBJECT_THIS_FRAME;
		static GameNative<void(Object object), 0xADBE4809F19F927A> _MARK_OBJECT_FOR_DELETION;
	};
};