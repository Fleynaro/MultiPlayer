#include <Program.h>
#include <SdaInterface.h>
#include <FunctionTag/FunctionTag.h>

Program* g_program = nullptr;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DebugOutput("sda.dll loaded successfully!");
		g_program = new Program(hModule);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}