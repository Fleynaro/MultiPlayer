#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class FIRE : public IGameNativeGroup<FIRE>
	{
	public:
		static GameNative<Hash(float X, float Y, float Z, int maxChildren, BOOL isGasFire), 0x6B83617E04503888> START_SCRIPT_FIRE;
		static GameNative<void(int fireHandle), 0x7FF548385680673F> REMOVE_SCRIPT_FIRE;
		static GameNative<Ped(Ped entity), 0xF6A9D9708F6F23DF> START_ENTITY_FIRE;
		static GameNative<void(Entity entity), 0x7F0DD2EBBB651AFF> STOP_ENTITY_FIRE;
		static GameNative<BOOL(Entity entity), 0x28D3FED7190D3A0B> IS_ENTITY_ON_FIRE;
		static GameNative<int(float x, float y, float z, float radius), 0x50CAD495A460B305> GET_NUMBER_OF_FIRES_IN_RANGE;
		static GameNative<void(float x, float y, float z, float radius), 0x056A8A219B8E829F> STOP_FIRE_IN_RANGE;
		static GameNative<BOOL(Vector3* outPosition, float x, float y, float z), 0x352A9F6BCF90081F> GET_CLOSEST_FIRE_POS;
		static GameNative<void(float x, float y, float z, int explosionType, float damageScale, BOOL isAudible, BOOL isInvisible, float cameraShake), 0xE3AD2BDBAEE269AC> ADD_EXPLOSION;
		static GameNative<void(Ped ped, float x, float y, float z, int explosionType, float damageScale, BOOL isAudible, BOOL isInvisible, float cameraShake), 0x172AA1B624FA1013> ADD_OWNED_EXPLOSION;
		static GameNative<void(Entity x, Entity y, Entity z, int explosionType, Hash explosionFx, float damageScale, BOOL isAudible, BOOL isInvisible, float cameraShake), 0x36DD3FE58B5E5212> ADD_EXPLOSION_WITH_USER_VFX;
		static GameNative<BOOL(int explosionType, float x1, float y1, float z1, float x2, float y2, float z2), 0x2E2EBA0EE7CED0E0> IS_EXPLOSION_IN_AREA;
		static GameNative<int(int explosionType, float x1, float y1, float z1, float x2, float y2, float z2), 0x6070104B699B2EF4> _0x6070104B699B2EF4;
		static GameNative<BOOL(int explosionType, float x, float y, float z, float radius), 0xAB0F816885B0E483> IS_EXPLOSION_IN_SPHERE;
		static GameNative<BOOL(int explosionType, float x1, float y1, float z1, float x2, float y2, float z2, float angle), 0xA079A6C51525DC4B> IS_EXPLOSION_IN_ANGLED_AREA;
		static GameNative<Entity(int explosionType, float x1, float y1, float z1, float x2, float y2, float z2, float radius), 0x14BA4BA137AF6CEC> _GET_PED_INSIDE_EXPLOSION_AREA;
	};
};