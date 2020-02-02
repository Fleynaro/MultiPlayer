
#include <stdio.h>
#include <windows.h>
#include <include\MinHook.h>


bool RemoteLoadLibW(HANDLE hProcess, PCWSTR pszLibFile)
{
	PWSTR     pszLibFileRemote = NULL;
	int iChars = 1 + lstrlenW(pszLibFile);
	int iSize = iChars * sizeof(WCHAR);  // calculate the size we need in the foreign process

	// allocate space for the string in the foreign process
	pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, iSize, MEM_COMMIT, PAGE_READWRITE);

	if (pszLibFileRemote == NULL)
		return false;

	// Copy the DLL path in to the foreign process
	if (!WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, iSize, NULL))
		return false;

	// all DLLs are mapped in the local address space of a process and in 99% of all cases
	// it's nt.dll and then the kernel so the relative address of kernel functions is equal in
	// all processes
	LPTHREAD_START_ROUTINE pfnThreadRtn = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32"), "LoadLibraryW");

	if (pfnThreadRtn == NULL)
		return false;

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);

	// unable to create foreign thread
	if (hThread == NULL)
		return false;

	// wait for the remote-thread to finish
	WaitForSingleObject(hThread, INFINITE);

	// everything went smoothly till here so we assume that the injection was successful
	if (pszLibFileRemote != NULL)
		VirtualFreeEx(hProcess, pszLibFileRemote, iSize, MEM_RELEASE);

	if (hThread != NULL)
		CloseHandle(hThread);

	if (hProcess != NULL)
		CloseHandle(hProcess);

	return true;
}

bool RemoteLoadLibA(HANDLE hProcess, PCSTR pszLibFile)
{
	PWSTR pszLibFileW = NULL;  // pointer to the UNICODE string

	// allocate space for the converted UNICODE string
	pszLibFileW = (PWSTR)malloc((lstrlenA(pszLibFile) + 1) * sizeof(WCHAR));

	// convert from ANSI to UNICODE
	wsprintfW(pszLibFileW, L"%S", pszLibFile);

	// call the UNICODE version
	bool result = RemoteLoadLibW(hProcess, pszLibFileW);

	free(pszLibFileW);

	return result;
}







typedef BOOL (WINAPI *tCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
tCreateProcessA CreateProcessA_orig = NULL;
BOOL WINAPI CreateProcessA_proxy(
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
)
{
	if (!CreateProcessA_orig(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation))
	{
		MessageBox(NULL, "Could not start GTA5.exe", NULL, MB_ICONEXCLAMATION | MB_OK);
		return false;
	}

	//загрузка нужных длл
	if (!strcmp(lpApplicationName, "GTA5.exe"))
	{
		WIN32_FIND_DATAA find;
		HANDLE search;
		if ((search = FindFirstFileA("FastLoader\\*.dll", &find)) != INVALID_HANDLE_VALUE)
		{
			do
			{
				if (strcmp(find.cFileName, "MultiPlayer.dll")) {
					continue;
				}

				char path[MAX_PATH] = "FastLoader\\";
				strcat_s(path, find.cFileName);
				if (!RemoteLoadLibA(lpProcessInformation->hProcess, path))
				{
					char tmp[512];
					sprintf_s(tmp, "Could not inject %s", find.cFileName);
					MessageBox(NULL, tmp, NULL, MB_ICONEXCLAMATION | MB_OK);
				}
			} while (FindNextFileA(search, &find));

		}

		if (MH_DisableHook(&CreateProcessA) != MH_OK) {
			return false;
		}
	}

	ResumeThread(lpProcessInformation->hThread);


	Sleep(500);


	//CloseHandle(lpProcessInformation->hProcess);
	//CloseHandle(lpProcessInformation->hThread);
	return true;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		//делает паузу
		MessageBox(NULL, "Loader injected to GTA Launcher. NEED TO ATTACH!", NULL, MB_ICONEXCLAMATION | MB_OK);

		if (MH_Initialize() != MH_OK) {
			return 1;
		}


		if (MH_CreateHook(&CreateProcessA, &CreateProcessA_proxy, reinterpret_cast<LPVOID*>(&CreateProcessA_orig)) != MH_OK) {
			return 1;
		}
		if (MH_EnableHook(&CreateProcessA) != MH_OK) {
			return 1;
		}
		
		//MessageBox(NULL, "Ќу че, поехали?", NULL, MB_ICONEXCLAMATION | MB_OK);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

