#pragma once
#include <main.h>

static void DebugOutput(const std::string& str) {
	OutputDebugString(str.c_str());
}