
#include "windows.h"
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include "initguid.h"
#include "dbgeng.h"
#include "Registration.h"
#include "IOCallbacks.hpp"
#include "DebugEventCallbacks.hpp"
#include "Common.h"

const TCHAR* REGISTER_POST_MORTEM =		TEXT("I");
const TCHAR* UNREGISTER_POST_MORTEM =	TEXT("uI");
const TCHAR* PID_OPTION =				TEXT("p");
const TCHAR* EID_OPTION =				TEXT("e");
const TCHAR* DIR_PATH_OPTION =			TEXT("o");

const TCHAR* BASIC_COMMAND_LINE =		TEXT("-p %ld -e %ld");

void PrintHelp()
{
	_tprintf(TEXT("FuzzwareDBG.exe 2008 (c) dave@fuzzware.net\n"));
	_tprintf(TEXT("\n"));
	_tprintf(TEXT("Usage:\n"));
	_tprintf(TEXT("    FuzzwareDBG [option]\n"));
	_tprintf(TEXT("\n"));
	_tprintf(TEXT("Options\n"));
	_tprintf(TEXT("    -%s [-%s dirpath]     Register FuzzwareDBG as the post mortem debugger\n"), REGISTER_POST_MORTEM, DIR_PATH_OPTION);
	_tprintf(TEXT("    -%s			Unregister FuzzwareDBG as the post mortem debugger\n"), UNREGISTER_POST_MORTEM);
	_tprintf(TEXT("    -%s PID [-%s EID][-%s dirpath]\n"), PID_OPTION, EID_OPTION, DIR_PATH_OPTION);
	_tprintf(TEXT("        -%s PID	        Attach to process with given Process Id (PID)\n"), PID_OPTION);
	_tprintf(TEXT("        -%s EID	        Event ID to signal once attached (used by Error Reporting)\n"), EID_OPTION);
	_tprintf(TEXT("        -%s dirpath      Specify output path, default is exe directory\n"), DIR_PATH_OPTION);
}

/*
* Returns true if the command line option exists, otherwise false
*/
bool CommandLineOptionExists(int argc, TCHAR** argv, const TCHAR* pszOption)
{
	for(int i = 1; i < argc; i++)
	{
		TCHAR* cmd = argv[i];

		if((_tcslen(cmd) > 1) && (('/' == *cmd) || ('-' == *cmd)))
		{
			if(0 == _tcsicmp(cmd + 1, pszOption))
			{
				return true;
			}
		}
	}
	return false;
}

/*
* Finds the command line option and returns the argument following it, if there is one.
* If there is no following argument or the option does not exist, it returns NULL.
*/
TCHAR* CommandLineOptionValue(int argc, TCHAR** argv, const TCHAR* pszOption)
{
	for(int i = 1; i < argc; i++)
	{
		TCHAR* cmd = argv[i];

		if((_tcslen(cmd) > 1) && (('/' == *cmd) || ('-' == *cmd)))
		{
			if(0 == _tcsicmp(cmd + 1, pszOption))
			{
				if(i + 1 < argc)
					return argv[i + 1];
				else
					return NULL;
			}
		}
	}
	return NULL;
}

void ProcessCommandLine(int argc, TCHAR** argv)
{
	TCHAR* cmd;
	// Try to process the command to register or unregister as the post mortem debugger

	if(CommandLineOptionExists(argc, argv, REGISTER_POST_MORTEM))
	{
		TCHAR szFilename[MAX_PATH];
		DWORD ccFilename = GetModuleFileName(NULL, szFilename, MAX_PATH);
		if(MAX_PATH == ccFilename)
		{
			PrintHelp();
			_tprintf(TEXT("\n\nThe full path to FuzzwareDBG is too long, it needs to be less than MAX_PATH.\n"));
			return;
		}

		// Construct the basic command line  i.e. "fullpathtoexe" -p %ld -e %ld
		size_t ccCmdLine = ccFilename + 3 + _tcslen(BASIC_COMMAND_LINE);
		TCHAR* pszCmdLine = (TCHAR*)malloc( (ccCmdLine + 1) * sizeof(TCHAR) );
		if(NULL == pszCmdLine)
		{
			_tprintf(TEXT("\n\nOut of memory.\n"));
			return;
		}
		pszCmdLine[0] = TEXT('\0');
		StringCchCat(pszCmdLine, ccCmdLine + 1, TEXT("\""));
		StringCchCat(pszCmdLine, ccCmdLine + 1, szFilename);
		StringCchCat(pszCmdLine, ccCmdLine + 1, TEXT("\" "));
		StringCchCat(pszCmdLine, ccCmdLine + 1, BASIC_COMMAND_LINE);

		if(CommandLineOptionExists(argc, argv, DIR_PATH_OPTION))	// Check if output directory was specified
		{
			cmd = CommandLineOptionValue(argc, argv, DIR_PATH_OPTION);
			if(NULL != cmd)
			{
				ccCmdLine += (_tcslen(cmd) + _tcslen(DIR_PATH_OPTION) + 5);
				pszCmdLine = (TCHAR*)realloc(pszCmdLine, (ccCmdLine + 1) * sizeof(TCHAR) );
				if(NULL == pszCmdLine)
				{
					_tprintf(TEXT("\n\nOut of memory.\n"));
					return;
				}
				StringCchCat(pszCmdLine, ccCmdLine + 1, TEXT(" -"));
				StringCchCat(pszCmdLine, ccCmdLine + 1, DIR_PATH_OPTION);
				StringCchCat(pszCmdLine, ccCmdLine + 1, TEXT(" \""));
				StringCchCat(pszCmdLine, ccCmdLine + 1, cmd);
				StringCchCat(pszCmdLine, ccCmdLine + 1, TEXT("\""));
			}
			else
			{
				PrintHelp();
				return;
			}
		}

		// Make sure there are no extraneous command line arguments
		if((2 == argc) || (4 == argc))
			RegisterPostMortem(pszCmdLine);
		else
			PrintHelp();

		free(pszCmdLine);
		return;
	}

	if(CommandLineOptionExists(argc, argv, UNREGISTER_POST_MORTEM))
	{
		// Make sure there are no extraneous command line arguments
		if(2 == argc)
			UnregisterPostMortem();
		else
			PrintHelp();

		return;
	}



	/*
	* Assume the command line is wanting us to attach
	*/
	ULONG ulPID = 0;
	bool bUsingEID = false;
	HANDLE hEID = NULL;
	TCHAR* pcDirPath = NULL;
	// Find PID
	cmd = CommandLineOptionValue(argc, argv, PID_OPTION);
	if(NULL != cmd)
	{
		// Convert PID to number
		ulPID = (ULONG)_tstoi(cmd);
	}
	else
	{
		PrintHelp();
		return;
	}
	
	// Find EID, it is not a mandatory option
	cmd = CommandLineOptionValue(argc, argv, EID_OPTION);
	if(NULL != cmd)
	{
		// Convert EID to number
		hEID = (HANDLE)_tstoi(argv[4]);
		bUsingEID = true;
	}
	
	// Get the directory path
	cmd = CommandLineOptionValue(argc, argv, DIR_PATH_OPTION);
	if(NULL != cmd)
	{
		// Store directory path
		size_t ccDestSize = _tcslen(cmd);
		pcDirPath = (TCHAR*)malloc((ccDestSize + 1) * sizeof(TCHAR));
		if(NULL == pcDirPath)
		{
			_tprintf(TEXT("\n\nOut of memory.\n"));
			return;
		}
		StringCchCopy(pcDirPath, ccDestSize + 1, cmd);
		pcDirPath[ccDestSize] = 0;

	}
	else if(CommandLineOptionExists(argc, argv, DIR_PATH_OPTION))
	{
		PrintHelp();
		return;
	}
	else
	{
		// Set to default, the directory of the exe
		TCHAR szFilename[MAX_PATH];
		if(MAX_PATH > GetModuleFileName(NULL, szFilename, MAX_PATH))
		{
			TCHAR* pcLastSlash = _tcsrchr(szFilename, '\\');
			*(pcLastSlash + 1) = 0;
			pcDirPath = CopyString(szFilename);
			/*size_t iDestSize = _tcslen(szFilename);
			pcDirPath = (TCHAR*)malloc((iDestSize + 1) * sizeof(TCHAR));
			StringCchCopy(pcDirPath, iDestSize + 1, szFilename);
			pcDirPath[iDestSize] = 0;*/
		}
		else
		{
			_tprintf(TEXT("\n\nThe full path to FuzzwareDBG is too long, it needs to be less than MAX_PATH.\n"));
			return;
		}
	}

	// Check parameter count
	int iParamCount = 3;	// exe name + -p + PID
	if(bUsingEID)
		iParamCount += 2;
	if(CommandLineOptionExists(argc, argv, DIR_PATH_OPTION))
		iParamCount += 2;

	if(iParamCount != argc)
	{
		PrintHelp();
		return;
	}

	/*
	*  If we get to here we are ready to run the debugger
	*/

	HRESULT hr;
	// We have the PID and the output directory so run debugger
	FuzzwareDBG* pFuzzwareDBG = new FuzzwareDBG();
	BSTR bstrDirPath;
#ifdef UNICODE
	bstrDirPath = SysAllocString(pcDirPath);
#else
	wchar_t* pwcDirString = NULL;
	int iSize = MultiByteToWideChar(CP_ACP, 0, pcDirPath, -1, pwcDirString, 0);
	pwcDirString = (wchar_t*)malloc(iSize * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, pcDirPath, -1, pwcDirString, iSize);
	bstrDirPath = SysAllocString(pwcDirString);
	free(pwcDirString);
#endif

	// Set the output directory
	hr = pFuzzwareDBG->SetOutputDir(bstrDirPath);
	if(!SUCCEEDED(hr))
	{
		printf("Failed to set output dir\n");
	}

	// Set the event to signal after the debugger has attached
	if(bUsingEID)
		pFuzzwareDBG->SetPMAttachCompleteEvent(hEID);
	
	// Attach and run the process
	hr = pFuzzwareDBG->AttachToProcess(ulPID);
	hr = pFuzzwareDBG->RunProcess(&ulPID);

	// Wait until we have finished debugging
	pFuzzwareDBG->WaitForSessionToFinish();

	// Clean up
	delete pFuzzwareDBG;
	free(pcDirPath);
	
	return;
}


int main(int argc, TCHAR** argv)
{
	/*
	* Check if the command line parameters are asking us to register or unregister
	*/
	if(2 == argc)
	{	
		if(CommandLineOptionExists(argc, argv, TEXT("RegServer")))
		{
			if(S_OK != DllRegisterServer())
				return 1;
			return 0;
		}
		if(CommandLineOptionExists(argc, argv, TEXT("UnregServer")))
		{
			if(S_OK != DllUnregisterServer())
				return 1;
			return 0;
		}
		// Not sure what this is but it seems to be being passed in.
		// 15/5/08 This may be COM thing to indicate to the exe not to create an GUI components
		// and execute the exe as if it was embedded in the calling application (apparently
		// this similiar to what IE does when running a LocalServer ActiveX control)
		if(CommandLineOptionExists(argc, argv, TEXT("Embedding")))
		{
			//__asm
			//{
				//int 3;
			//}
			RegisterClassObject();
			return 0;
		}
	}

	/*
	* If there are no command line arguments then print out help
	*/
	if((1 == argc) || (6 == argc) || (argc > 7))
	{
		PrintHelp();
		return 0;
	}
	else
	{
		ProcessCommandLine(argc, argv);
	}

	return 0;

	//HRESULT hr;
	//IDebugClient2* pIDebugClient2 = NULL;
	//hr = DebugCreate(IID_IDebugClient2, (PVOID*)(&pIDebugClient2));
	//if(S_OK != hr)
	//{
	//	printf("Could not create IID_IDebugClient2.  hr = %#x\n", hr);
	//	return 0;
	//}
	//printf("Created IID_IDebugClient2 successfully\n");

	//IDebugControl* pIDebugControl = NULL;
	//hr = DebugCreate(IID_IDebugControl, (PVOID*)(&pIDebugControl));
	//if(S_OK != hr)
	//{
	//	printf("Could not create IID_pIDebugControl.  hr = %#x\n", hr);
	//	return 0;
	//}
	//printf("Created IID_pIDebugControl successfully\n");
	//
	///*PDEBUG_EVENT_CALLBACKS poEventCallbacks = NULL;
	//hr = pIDebugClient2->GetEventCallbacks(&poEventCallbacks);
	//if(S_OK != hr)
	//{
	//	printf("Failed to get event callbacks.  hr = %#x\n", hr);
	//}
	//if(NULL != poEventCallbacks)
	//{
	//	printf("Got event callbacks.  add = %#x\n", poEventCallbacks);
	//}*/

	//IDebugSystemObjects* pIDebugSystemObjects = NULL;
	//hr = DebugCreate(IID_IDebugSystemObjects, (PVOID*)(&pIDebugSystemObjects));
	//if(S_OK != hr)
	//{
	//	printf("Could not create IID_IDebugSystemObjects.  hr = %#x\n", hr);
	//	return 0;
	//}

	//DebugEventCallbacks* poDebugEventCallbacks = new DebugEventCallbacks((IDebugClient2*)pIDebugClient2, pIDebugSystemObjects, "");
	//hr = pIDebugClient2->SetEventCallbacks((PDEBUG_EVENT_CALLBACKS)poDebugEventCallbacks);
	//if(S_OK != hr)
	//{
	//	printf("Failed to set event callbacks.  hr = %#x\n", hr);
	//}

	//IOCallbacks* poIOCallbacks = new IOCallbacks();
	//hr = pIDebugClient2->SetInputCallbacks((IDebugInputCallbacks*)poIOCallbacks);
	//if(S_OK != hr)
	//{
	//	printf("Failed to set input callbacks.  hr = %#x\n", hr);
	//}

	//hr = pIDebugClient2->SetOutputCallbacks((IDebugOutputCallbacks*)poIOCallbacks);
	//if(S_OK != hr)
	//{
	//	printf("Failed to set output callbacks.  hr = %#x\n", hr);
	//}

	//char* line = "\"C:\\Program Files\\Real\\RealPlayer\\realplay.exe\" G:\\Tools\\Fuzzware\\Examples\\Real\\sorted\\smplfsys!RMACreateInstance+0xb74\\mov-ByteLengthOfdref-0-ReplaceInteger-2.mov";
	//hr = pIDebugClient2->CreateProcessAndAttach(0, line, DEBUG_PROCESS, 0, 0);
	//if(S_OK != hr)
	//{
	//	printf("Failed to create process.  hr = %#x\n", hr);
	//	pIDebugClient2->Release();
	//	return 0;
	//}
	//
	//hr = pIDebugClient2->CreateProcessAndAttach(0, "\"C:\\Program Files\\Real\\RealPlayer\\realplay.exe\" G:\\Tools\\Fuzzware\\Examples\\Real\\sorted\\smplfsys!RMACreateInstance+0xb74\\mov-ByteLengthOfdref-0-ReplaceInteger-2.mov", DEBUG_PROCESS, 0, 0);
	//if(S_OK != hr)
	//{
	//	printf("Failed to create process.  hr = %#x\n", hr);
	//	pIDebugClient2->Release();
	//	return 0;
	//}

	//while(1)
	//{
	//	// Should return E_UNEXPECTED when process exits, but maybe also if there is an outstanding request for input
	//	hr = pIDebugControl->WaitForEvent(0, INFINITE);
	//	if(S_OK != hr)
	//	{
	//		printf("WaitForEvent returned an error.  hr = %#x\n", hr);
	//		break;
	//	}

	//	hr = pIDebugControl->SetExecutionStatus(DEBUG_STATUS_GO);
	//	if(S_OK != hr)
	//	{
	//		printf("Failed to set execution status.  hr = %#x\n", hr);
	//	}

	//	/*hr = pIDebugControl->Execute(DEBUG_OUTCTL_IGNORE, "g", DEBUG_EXECUTE_NOT_LOGGED);
	//	if(S_OK != hr)
	//	{
	//		printf("Failed to execute command.  hr = %#x\n", hr);
	//	}*/
	//}
	//
	//hr = pIDebugClient2->DetachProcesses();
	//if(S_OK != hr)
	//{
	//	printf("Failed to detach process.  hr = %#x\n", hr);
	//	return 0;
	//}

	//pIDebugControl->Release();
	//pIDebugClient2->Release();

	//return 0;
}