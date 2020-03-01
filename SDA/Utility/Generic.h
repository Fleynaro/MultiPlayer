#pragma once

#include "main.h"
#include <stdarg.h>
#include <memory>
#include <chrono>
#include <regex>
#include <cctype>
#include <sstream>


namespace Generic
{
	namespace String {
		extern std::vector<std::string> Split(const std::string& input, const std::string& regex);
		extern void Replace(std::string& source, const std::string& from, const std::string& to);
		
		extern std::string ToLower(std::string source);
		extern std::string ToUpper(std::string source);

		extern uint64_t HexToNumber(std::string source);
		extern std::string NumberToHex(uint64_t number);

		extern bool is_number(const std::string& s);

		std::wstring s2ws(const std::string& str);
		std::string ws2s(const std::wstring& wstr);

		static inline void ltrim(std::string& s);
		static inline void rtrim(std::string& s);

		extern void replaceSymbolWithin(std::string& source, const char bounder[2], const char from, const char to = ' ');

		std::string format(const std::string fmt_str, ...);
	};

	namespace Date {
		namespace View {
			constexpr const char* Full = "%Y-%m-%d %H:%M:%S";
			constexpr const char* Date = "%Y-%m-%d";
			constexpr const char* Time = "%H:%M:%S";
		};

		extern std::string format(std::chrono::system_clock::time_point time_point, std::string format = View::Full);
	};
};

