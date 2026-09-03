#pragma once
#include <main.h>

static bool DebugOutput_Console = true;

static void DebugOutput(const std::string& str) {
	if (DebugOutput_Console) {
		std::cout << str << std::endl;
	}
	else {
		OutputDebugString(str.c_str());
	}
}