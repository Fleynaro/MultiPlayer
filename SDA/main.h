#pragma once
#pragma warning( disable : 4250)

// libraries from std
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <queue>
#include <stack>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <random>
#include <functional>
#include <filesystem>
#include <stdarg.h>
#include <memory>
#include <chrono>
#include <regex>
#include <cctype>

// windows
#include <winsock2.h>
#include <windows.h>
#include <immintrin.h>
#include <d3d11.h>

// extends the standart library
#include <Utils/Helper.h>
#include <Vendor/json/json.hpp>

// namespaces
using json = nlohmann::json;
namespace fs = std::filesystem;