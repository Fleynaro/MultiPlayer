#pragma once


#include <windows.h>
#include <string>
#include <regex>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <memory>
#include <algorithm>
#include <functional>
#include <TlHelp32.h>
#include <Shlwapi.h>

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <array>
#include <deque>
#include <map>
#include <set>



#include "Vendor/json/json.hpp"
using json = nlohmann::json;


#pragma comment(lib, "libMinHook.x64_vc2017.lib")
#pragma comment(lib, "Winmm.Lib")




#define STATIC_FIELD_INIT(field) decltype(##field) ##field