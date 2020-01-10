#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class WORLDPROBE : public IGameNativeGroup<WORLDPROBE>
	{
	public:
		static GameNative<int(float x1, float y1, float z1, float x2, float y2, float z2, int flags, Entity ent, int p8), 0x7EE9F5D83DD4F90E> START_SHAPE_TEST_LOS_PROBE;
		static GameNative<int(float x1, float y1, float z1, float x2, float y2, float z2, int flags, Entity entity, int p8), 0x377906D8A31E5586> _START_SHAPE_TEST_RAY;
		static GameNative<int(Entity entity, int flags1, int flags2), 0x052837721A854EC7> START_SHAPE_TEST_BOUNDING_BOX;
		static GameNative<int(float x, float y, float z, float x1, float y2, float z2, float rotX, float rotY, float rotZ, Any p9, Any p10, Any entity, Any p12), 0xFE466162C4401D18> START_SHAPE_TEST_BOX;
		static GameNative<int(Entity entity, int flags1, int flags2), 0x37181417CE7C8900> START_SHAPE_TEST_BOUND;
		static GameNative<int(float x1, float y1, float z1, float x2, float y2, float z2, float radius, int flags, Entity entity, int p9), 0x28579D1B8F8AAC80> START_SHAPE_TEST_CAPSULE;
		static GameNative<int(float x1, float y1, float z1, float x2, float y2, float z2, float radius, int flags, Entity entity, Any p9), 0xE6AC6C45FBE83004> _START_SHAPE_TEST_CAPSULE_2;
		static GameNative<int(Vector3* pVec1, Vector3* pVec2, int flag, Entity entity, int flag2), 0xFF6BE494C7987F34> _START_SHAPE_TEST_SURROUNDING_COORDS;
		static GameNative<int(int rayHandle, BOOL* hit, Vector3* endCoords, Vector3* surfaceNormal, Entity* entityHit), 0x3D87450E15D98694> GET_SHAPE_TEST_RESULT;
		static GameNative<int(int rayHandle, BOOL* hit, Vector3* endCoords, Vector3* surfaceNormal, Hash* materialHash, Entity* entityHit), 0x65287525D951F6BE> _GET_SHAPE_TEST_RESULT_EX;
		static GameNative<void(Hash entityHit), 0x2B3334BCA57CD799> _SHAPE_TEST_RESULT_ENTITY;
	};
};