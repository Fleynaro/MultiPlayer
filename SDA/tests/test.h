#pragma once
//SDA
#include <Program.h>

//gtest
#define _DEBUG
#undef NDEBUG
#include "gtest/gtest.h"

int main(int argc, char** argv);
int setRot(int a, float x, float y, float z, int c);

const char* g_testFuncName = "setRot";