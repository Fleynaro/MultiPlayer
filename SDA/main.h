#pragma once

#include <fstream>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <queue>
#include <stack>
#include <atomic>
#include <thread>
#include <mutex>
#include <random>
#include <string>
#include <functional>

#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <immintrin.h>

#include <d3d11.h>


#include <Vendor/json/json.hpp>
using json = nlohmann::json;

#include "Utils/enum.h"


#define MYDEBUG

class DebugInfo {
#ifdef MYDEBUG
	std::string m_info = "Not info.";
#endif
public:
	DebugInfo() = default;

	void setInfo(const std::string& info) {
#ifdef MYDEBUG
		m_info = info;
#endif
	}
};

#define SET_INFO(message) setInfo("" + std::to_string(__LINE__)  + ": " + ##message)