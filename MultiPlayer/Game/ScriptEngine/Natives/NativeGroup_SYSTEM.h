#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class SYSTEM : public IGameNativeGroup<SYSTEM>
	{
	public:
		static GameNative<void(int ms), 0x4EDE34FBADD967A6> WAIT;
		static GameNative<int(char* scriptName, int stackSize), 0xE81651AD79516E48> START_NEW_SCRIPT;
		static GameNative<int(char* scriptName, Any* args, int argCount, int stackSize), 0xB8BA7F44DF1575E1> START_NEW_SCRIPT_WITH_ARGS;
		static GameNative<int(Hash scriptHash, int stackSize), 0xEB1C67C3A5333A92> START_NEW_SCRIPT_WITH_NAME_HASH;
		static GameNative<int(Hash scriptHash, Any* args, int argCount, int stackSize), 0xC4BB298BD441BE78> START_NEW_SCRIPT_WITH_NAME_HASH_AND_ARGS;
		static GameNative<int(), 0x83666F9FB8FEBD4B> TIMERA;
		static GameNative<int(), 0xC9D9444186B5A374> TIMERB;
		static GameNative<void(int value), 0xC1B1E9A034A63A62> SETTIMERA;
		static GameNative<void(int value), 0x5AE11BC36633DE4E> SETTIMERB;
		static GameNative<float(), 0x0000000050597EE2> TIMESTEP;
		static GameNative<float(float value), 0x0BADBFA3B172435F> SIN;
		static GameNative<float(float value), 0xD0FFB162F40A139C> COS;
		static GameNative<float(float value), 0x71D93B57D07F9804> SQRT;
		static GameNative<float(float base, float exponent), 0xE3621CC40F31FE2E> POW;
		static GameNative<float(float x, float y, float z), 0x652D2EEEF1D3E62C> VMAG;
		static GameNative<float(float x, float y, float z), 0xA8CEACB4F35AE058> VMAG2;
		static GameNative<float(float x1, float y1, float z1, float x2, float y2, float z2), 0x2A488C176D52CCA5> VDIST;
		static GameNative<float(float x1, float y1, float z1, float x2, float y2, float z2), 0xB7A628320EFF8E47> VDIST2;
		static GameNative<int(int value, int bitShift), 0xEDD95A39E5544DE8> SHIFT_LEFT;
		static GameNative<int(int value, int bitShift), 0x97EF1E5BCE9DC075> SHIFT_RIGHT;
		static GameNative<int(float value), 0xF34EE736CF047844> FLOOR;
		static GameNative<int(float value), 0x11E019C8F43ACC8A> CEIL;
		static GameNative<int(float value), 0xF2DB717A73826179> ROUND;
		static GameNative<float(int value), 0xBBDA792448DB5A89> TO_FLOAT;
	};
};