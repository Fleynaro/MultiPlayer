#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class WATER : public IGameNativeGroup<WATER>
	{
	public:
		static GameNative<BOOL(float x, float y, float A, float* height), 0xF6829842C06AE524> GET_WATER_HEIGHT;
		static GameNative<BOOL(float B, float y, float z, float* height), 0x8EE6B53CE13A9794> GET_WATER_HEIGHT_NO_WAVES;
		static GameNative<BOOL(float x1, float y1, float z1, float x2, float y2, float z2, Vector3* result), 0xFFA5D878809819DB> TEST_PROBE_AGAINST_WATER;
		static GameNative<int(float x1, float y1, float z1, float x2, float y2, float z2, int type, Vector3* result), 0x8974647ED222EA5F> TEST_PROBE_AGAINST_ALL_WATER;
		static GameNative<BOOL(float x, float y, float z, float p3, float* height), 0x2B3451FA1E3142E2> TEST_VERTICAL_PROBE_AGAINST_ALL_WATER;
		static GameNative<void(float x, float y, float radius, float height), 0xC443FD757C3BA637> MODIFY_WATER;
		static GameNative<int(float xLow, float yLow, float xHigh, float yHigh, float height), 0xFDBF4CDBC07E1706> _ADD_CURRENT_RISE;
		static GameNative<void(int riseHandle), 0xB1252E3E59A82AAF> _REMOVE_CURRENT_RISE;
		static GameNative<void(float intensity), 0xB96B00E976BE977F> _SET_CURRENT_INTENSITY;
		static GameNative<float(), 0x2B2A2CC86778B619> _GET_CURRENT_INTENSITY;
		static GameNative<void(), 0x5E5E99285AE812DB> _RESET_CURRENT_INTENSITY;
	};
};