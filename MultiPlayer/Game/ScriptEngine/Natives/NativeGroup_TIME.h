#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class TIME : public IGameNativeGroup<TIME>
	{
	public:
		static GameNative<void(int hour, int minute, int second), 0x47C3B5848C3E45D8> SET_CLOCK_TIME;
		static GameNative<void(BOOL toggle), 0x4055E40BD2DBEC1D> PAUSE_CLOCK;
		static GameNative<void(int hour, int minute, int second), 0xC8CA9670B9D83B3B> ADVANCE_CLOCK_TIME_TO;
		static GameNative<void(int hours, int minutes, int seconds), 0xD716F30D8C8980E2> ADD_TO_CLOCK_TIME;
		static GameNative<int(), 0x25223CA6B4D20B7F> GET_CLOCK_HOURS;
		static GameNative<int(), 0x13D2B8ADD79640F2> GET_CLOCK_MINUTES;
		static GameNative<int(), 0x494E97C2EF27C470> GET_CLOCK_SECONDS;
		static GameNative<void(int day, int month, int year), 0xB096419DF0D06CE7> SET_CLOCK_DATE;
		static GameNative<int(), 0xD972E4BD7AEB235F> GET_CLOCK_DAY_OF_WEEK;
		static GameNative<int(), 0x3D10BC92A4DB1D35> GET_CLOCK_DAY_OF_MONTH;
		static GameNative<int(), 0xBBC72712E80257A1> GET_CLOCK_MONTH;
		static GameNative<int(), 0x961777E64BDAF717> GET_CLOCK_YEAR;
		static GameNative<int(), 0x2F8B4D1C595B11DB> GET_MILLISECONDS_PER_GAME_MINUTE;
		static GameNative<void(int* year, int* month, int* day, int* hour, int* minute, int* second), 0xDA488F299A5B164E> GET_POSIX_TIME;
		static GameNative<void(int* year, int* month, int* day, int* hour, int* minute, int* second), 0x8117E09A19EEF4D3> _GET_UTC_TIME;
		static GameNative<void(int* year, int* month, int* day, int* hour, int* minute, int* second), 0x50C7A99057A69748> GET_LOCAL_TIME;
	};
};