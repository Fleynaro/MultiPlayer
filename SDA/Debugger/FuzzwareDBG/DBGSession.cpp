
#include "DBGSession.hpp"
#include <stdio.h>
#include <io.h>
#include <direct.h>
#include <strsafe.h>
#include "Common.h"

DBGSession::DBGSession()
{
	m_pIDebugClient = NULL;
	m_pIDebugControl = NULL;
	m_pIDebugSystemObjects = NULL;
	m_poDebugEventCallbacks = NULL;
	m_poIOCallbacks = NULL;

	m_pcRemoteOptions = NULL;
	m_pcCommandLine = NULL;
	m_PID = 0;
	m_hSessionFinished = 0;
	m_bSessionFinished = true;
	m_bKillSession = false;
	m_bSetAttachCompleteEvent = false;
	m_hPMAttachCompleteEvent = 0;
	
	m_pcOutputDir = NULL;
	m_pcCrashFileComment = NULL;
	m_bDebuggingToolsInstalled = false;
}

DBGSession::~DBGSession()
{
	UninitialiseDbgEngClient();

	free(m_pcRemoteOptions);
	free(m_pcCommandLine);
	free(m_pcOutputDir);
	free(m_pcCrashFileComment);
}

void DBGSession::SetRemoteOptions(TCHAR* pcRemoteOptions)
{
	if(NULL != m_pcRemoteOptions)
		free(m_pcRemoteOptions);

	m_pcRemoteOptions = CopyString(pcRemoteOptions);
}

void DBGSession::SetCommandLine(TCHAR* pcCommandLine)
{
	if(NULL != m_pcCommandLine)
		free(m_pcCommandLine);

	m_pcCommandLine = CopyString(pcCommandLine);
	
	m_PID = 0;
}

void DBGSession::SetProcessIdToAttach(unsigned long PID)
{
	m_PID = PID;
	m_pcCommandLine = NULL;
}

void DBGSession::SetSessionFinishedEvent(HANDLE hSessionFinished)
{
	m_hSessionFinished = hSessionFinished;
}

void DBGSession::SetPMAttachCompleteEvent(HANDLE hAttachComplete)
{
	m_bSetAttachCompleteEvent = true;
	m_hPMAttachCompleteEvent = hAttachComplete;
}

unsigned long DBGSession::GetProcessId()
{
	return m_PID;
}

void DBGSession::SetOutputDir(TCHAR* pcOutputDir)
{
	if(NULL != m_pcOutputDir)
		free(m_pcOutputDir);

	m_pcOutputDir = CopyString(pcOutputDir);
}

void DBGSession::SetCrashFileComment(TCHAR* pcCrashFileComment)
{
	if(NULL != m_pcCrashFileComment)
		free(m_pcCrashFileComment);

	m_pcCrashFileComment = CopyString(pcCrashFileComment);
}

/*
* If WinDbg is installed then DbgEng.dll does not exist in the dll search path,
* so we try to find DbgEng.dll and add that dir to the search path.
*/
void DBGSession::SetDbgEngSearchPath()
{
	TCHAR* l_DllName = TEXT("dbgeng.dll");

	if(!m_bDebuggingToolsInstalled)
	{
#if (_WIN32_WINNT > 0x0502)

		TCHAR* l_SearchPaths[] = {
			TEXT("%HOMEDRIVE%\\Debuggers\\"),
			TEXT("%HOMEDRIVE%\\Debugging Tools for Windows\\"),
			TEXT("%PROGRAMFILES%\\Debugging Tools for Windows\\"),
			TEXT("%HOMEDRIVE%\\Debugging Tools for Windows (x86)\\"),
			TEXT("%PROGRAMFILES%\\Debugging Tools for Windows (x86)\\"),
			TEXT("%PROGRAMFILES%\\Debugging Tools for Windows (x64)\\"),
			TEXT("%HOMEDRIVE%\\Debugging Tools for Windows (x64)\\"),
			TEXT("%ProgramW6432%\\Debugging Tools for Windows (x86)\\"),
			TEXT("%ProgramW6432%\\Debugging Tools for Windows (x64)\\"),
		};

		// Go through each possible path and see if we can find dbgeng.dll
		for(int i = 0; i < sizeof(l_SearchPaths)/sizeof(*l_SearchPaths); i++)
		{
			size_t szSize = ExpandEnvironmentStrings(l_SearchPaths[i], NULL, 0);
			TCHAR* pszDirPath = (TCHAR*)malloc( (szSize + 1) * sizeof(TCHAR) );
			if(NULL == pszDirPath)
			{
				_tprintf(TEXT("Out of memory\n"));
				return;
			}
			ExpandEnvironmentStrings(l_SearchPaths[i], pszDirPath, (DWORD)(szSize + 1));

			szSize = _tcslen(pszDirPath) + _tcslen(l_DllName) + 1;
			TCHAR* pszFilePath = (TCHAR*)malloc( (szSize) * sizeof(TCHAR) );
			if(NULL == pszDirPath)
			{
				_tprintf(TEXT("Out of memory\n"));
				return;
			}
			StringCchCopy(pszFilePath, szSize, pszDirPath);
			StringCchCat(pszFilePath, szSize, l_DllName);

			// Check if this dir exists
			if(0 == _access_s(pszFilePath, 0))
			{
				SetDllDirectory(pszDirPath);
				_tprintf(TEXT("%s was found in directory '%s'\n"), l_DllName, pszDirPath);
				free(pszFilePath);
				free(pszDirPath);
				m_bDebuggingToolsInstalled = true;
				break;
			}
			free(pszFilePath);
			free(pszDirPath);
		}
#endif
	}
	if(!m_bDebuggingToolsInstalled)
	{
		_tprintf(TEXT("%s was not found, using the default install version in the system directory.  To use a more"
			" recent version install 'Debugging Tools for Windows'.\n"), l_DllName);
	}
}

/*
* Gets DbgEng interfaces and sets up the callbacks
*/
void DBGSession::InitialiseDbgEngClient()
{
	SetDbgEngSearchPath();

	HRESULT hr;
	hr = DebugCreate(IID_IDebugClient5, (PVOID*)(&m_pIDebugClient));
	if(S_OK != hr)
	{
		_tprintf(TEXT("Could not create IID_IDebugClient5.  hr = %#x\nPlease download the latest version of 'Debugging Tools for Windows'.\n\n"), hr);
		_tprintf(TEXT("\nPress Enter to continue...\n"));
		getchar();
		exit(1);
	}
	//printf("Created IID_IDebugClient2 successfully\n");

	hr = DebugCreate(IID_IDebugControl4, (PVOID*)(&m_pIDebugControl));
	if(S_OK != hr)
	{
		_tprintf(TEXT("Could not create IID_IDebugControl4.  hr = %#x\nPlease download the latest version of 'Debugging Tools for Windows'.\n\n"), hr);
		_tprintf(TEXT("\nPress Enter to continue...\n"));
		getchar();
		exit(1);
	}
	//printf("Created IID_pIDebugControl successfully\n");

	hr = DebugCreate(IID_IDebugSystemObjects4, (PVOID*)(&m_pIDebugSystemObjects));
	if(S_OK != hr)
	{
		_tprintf(TEXT("Could not create IID_IDebugSystemObjects4.  hr = %#x\nPlease download the latest version of 'Debugging Tools for Windows'.\n\n"), hr);
		_tprintf(TEXT("\nPress Enter to continue...\n"));
		getchar();
		exit(1);
	}

	m_poDebugEventCallbacks = new DebugEventCallbacks(m_pIDebugClient, m_pIDebugSystemObjects, m_pcOutputDir);
	if(NULL == m_poDebugEventCallbacks)
	{
		_tprintf(TEXT("Out of memory creating DebugEventCallbacks.\n"));
	}
	if(NULL != m_pcCrashFileComment)
		m_poDebugEventCallbacks->SetCrashFileComment(m_pcCrashFileComment);

	hr = m_pIDebugClient->SetEventCallbacks((PDEBUG_EVENT_CALLBACKS)m_poDebugEventCallbacks);
	if(S_OK != hr)
	{
		_tprintf(TEXT("Failed to set event callbacks.  hr = %#x\n"), hr);
	}
	
	m_poIOCallbacks = new IOCallbacks();
	if(NULL == m_poIOCallbacks)
	{
		_tprintf(TEXT("Out of memory creating IOCallbacks.\n"));
	}
	hr = m_pIDebugClient->SetInputCallbacks((IDebugInputCallbacks*)m_poIOCallbacks);
	if(S_OK != hr)
	{
		_tprintf(TEXT("Failed to set input callbacks.  hr = %#x\n"), hr);
	}

	hr = m_pIDebugClient->SetOutputCallbacks((IDebugOutputCallbacks*)m_poIOCallbacks);
	if(S_OK != hr)
	{
		_tprintf(TEXT("Failed to set output callbacks.  hr = %#x\n"), hr);
	}

	hr = m_pIDebugControl->GetNumberEventFilters(&m_ulSpecificEventFiltersCount, &m_ulSpecificExceptionFiltersCount, &m_ulArbitraryExceptionFiltersCount);
	if(!SUCCEEDED(hr))
	{
		_tprintf(TEXT("Call to GetNumberEventFilters failed.  hr = %#x\n"), hr);
	}

}

void DBGSession::UninitialiseDbgEngClient()
{
	if(NULL != m_pIDebugSystemObjects)
	{
		m_pIDebugSystemObjects->Release();
		m_pIDebugSystemObjects = NULL;
	}
	if(NULL != m_pIDebugControl)
	{
		m_pIDebugControl->Release();
		m_pIDebugControl = NULL;
	}
	if(NULL != m_pIDebugClient)
	{
		m_pIDebugClient->Release();
		m_pIDebugClient = NULL;
	}

	// These need to be free'd AFTER m_pIDebugClient->Release() is called, otherwise an
	// exception occurs
	if(NULL != m_poIOCallbacks)
	{
		delete m_poIOCallbacks;
		m_poIOCallbacks = NULL;
	}
	if(NULL != m_poDebugEventCallbacks)
	{
		delete m_poDebugEventCallbacks;
		m_poDebugEventCallbacks = NULL;
	}
	
}

TCHAR* GetBreakStatus(ULONG BreakStatus)
{
	if(DEBUG_FILTER_BREAK == BreakStatus)
		return TEXT("DEBUG_FILTER_BREAK");
	if(DEBUG_FILTER_SECOND_CHANCE_BREAK == BreakStatus)
		return TEXT("DEBUG_FILTER_SECOND_CHANCE_BREAK");
	if(DEBUG_FILTER_OUTPUT == BreakStatus)
		return TEXT("DEBUG_FILTER_OUTPUT");
	if(DEBUG_FILTER_IGNORE == BreakStatus)
		return TEXT("DEBUG_FILTER_IGNORE");

	return TEXT("UNKNOWN");
}

TCHAR* GetHandledStatus(ULONG HandleStatus)
{
	if(DEBUG_FILTER_GO_HANDLED == HandleStatus)
		return TEXT("DEBUG_FILTER_GO_HANDLED");
	if(DEBUG_FILTER_GO_NOT_HANDLED == HandleStatus)
		return TEXT("DEBUG_FILTER_GO_NOT_HANDLED");

	return TEXT("UNKNOWN");
}

HRESULT GetEventFilterDesc(IDebugControl4* pIDebugControl, ULONG ulIndex, TCHAR** psDesc)
{
	ULONG DescCharCount = 0;
	HRESULT hr = pIDebugControl->GetEventFilterTextT(ulIndex, NULL, 0, &DescCharCount);

	if(SUCCEEDED(hr))
	{
		// Allocate space
		*psDesc = (TCHAR*)malloc( (DescCharCount + 1) * sizeof(TCHAR));
		if(NULL == psDesc)
		{
			return E_OUTOFMEMORY;
		}
		hr = pIDebugControl->GetEventFilterTextT(ulIndex, *psDesc, DescCharCount + 1, &DescCharCount);
	}
	return hr;
}

void DBGSession::ShowEventFilterHandling()
{
	HRESULT hr;
	DEBUG_SPECIFIC_FILTER_PARAMETERS* pFilterParameters = (DEBUG_SPECIFIC_FILTER_PARAMETERS*)malloc(m_ulSpecificEventFiltersCount * sizeof(DEBUG_SPECIFIC_FILTER_PARAMETERS));
	
	if(NULL != pFilterParameters)
	{
		// Print out the break and handle status of the Exception events
		hr = m_pIDebugControl->GetSpecificFilterParameters(0, m_ulSpecificEventFiltersCount, pFilterParameters);
		if(SUCCEEDED(hr))
		{
			for(ULONG i = 0; i < m_ulSpecificEventFiltersCount; i++)
			{
				TCHAR* psDesc;
				hr = GetEventFilterDesc(m_pIDebugControl, i, &psDesc);
				if(!SUCCEEDED(hr))
					psDesc = TEXT("UNKNOWN");
				_tprintf(TEXT("Status for %s filter (index %i): BreakStatus - %s  HandleStatus = %s\n"), psDesc, i, 
					GetBreakStatus(pFilterParameters[i].ExecutionOption), GetHandledStatus(pFilterParameters[i].ContinueOption));

				if(SUCCEEDED(hr))
					free(psDesc);
			}
		}
		free(pFilterParameters);
	}
}

void DBGSession::ShowExceptionFilterHandling()
{
	HRESULT hr;
	DEBUG_EXCEPTION_FILTER_PARAMETERS* pFilterParameters = (DEBUG_EXCEPTION_FILTER_PARAMETERS*)malloc(m_ulSpecificExceptionFiltersCount * sizeof(DEBUG_EXCEPTION_FILTER_PARAMETERS));

	if(NULL != pFilterParameters)
	{
		// Print out the break and handle status of the Exception events
		hr = m_pIDebugControl->GetExceptionFilterParameters(m_ulSpecificExceptionFiltersCount, NULL, m_ulSpecificEventFiltersCount, pFilterParameters);
		if(SUCCEEDED(hr))
		{
			for(ULONG i = 0; i < m_ulSpecificExceptionFiltersCount; i++)
			{
				TCHAR* psDesc;
				hr = GetEventFilterDesc(m_pIDebugControl, i, &psDesc);
				if(!SUCCEEDED(hr))
					psDesc = TEXT("UNKNOWN");
				_tprintf(TEXT("Status for %s filter (index %i): BreakStatus - %s  HandleStatus = %s\n"), psDesc, i, 
					GetBreakStatus(pFilterParameters[i].ExecutionOption), GetHandledStatus(pFilterParameters[i].ContinueOption));

				if(SUCCEEDED(hr))
					free(psDesc);
			}
		}
		free(pFilterParameters);
	}
}

TCHAR* DBGSession::GetCommandLine()
{
	ULONG64 ul64Server = 0;
	ULONG ulFlags = 0;
	ULONG ulExeNameSize = 2 * MAX_PATH;
	TCHAR* pcExeName = NULL;
	ULONG ulActualExeNameSize = 0;
	ULONG ulDescriptionSize = 2 * MAX_PATH;
	TCHAR* pcDescription = NULL;
	ULONG ulActionDescSize = 0;

	HRESULT hr;
	do
	{
		pcExeName = (TCHAR*)malloc( ulExeNameSize * sizeof(TCHAR) );
		pcDescription = (TCHAR*)malloc( ulDescriptionSize * sizeof(TCHAR) );
		if( (NULL != pcDescription) && (NULL != pcExeName) )
		{
			hr = m_pIDebugClient->GetRunningProcessDescription(ul64Server, m_PID, ulFlags, pcExeName, ulExeNameSize, &ulActualExeNameSize, pcDescription, ulDescriptionSize, &ulActionDescSize); 

			if(S_FALSE == hr)
			{
				free(pcExeName);
				ulExeNameSize = 2 * ulExeNameSize;
				free(pcDescription);
				ulDescriptionSize = 2 * ulDescriptionSize;
			}
		}
		else
			break;
	}
	while(S_FALSE == hr);

	
	if( (NULL != pcDescription) && (0 == _tcslen(pcDescription)) )
	{
		// Could try getting the PEB and getting the command line from that
		_tprintf(TEXT("IDebugClient->GetRunningProcessDescription failed to return a command line.\n"));
	}
	if(NULL != pcExeName)
		free(pcExeName);

	return pcDescription;
}

void DBGSession::RunSession()
{
	HRESULT hr;

	InitialiseDbgEngClient();

	//ShowEventFilterHandling();
	//ShowExceptionFilterHandling();

	if(NULL != m_pcCommandLine)
	{
		// Create the process and attach 
		hr = m_pIDebugClient->CreateProcessAndAttachT(
			0, 
			m_pcCommandLine, 
			DEBUG_ONLY_THIS_PROCESS, 
			0, 
			DEBUG_ATTACH_DEFAULT);

		if(SUCCEEDED(hr))
		{
			_tprintf(TEXT("\nCreating process: %s\n"), m_pcCommandLine);
		}
		else
		{
			_tprintf(TEXT("Failed to create process.  hr = %#x\n"), hr);
			return;
		}	
	}
	else if(m_PID > 0)
	{
		// Need to check the DEBUG_ATTACH_XXX parameter is right
		hr = m_pIDebugClient->AttachProcess(0, (ULONG)m_PID, DEBUG_ATTACH_DEFAULT);
		
		if(SUCCEEDED(hr))
		{
			_tprintf(TEXT("\nAttaching to process with PID: %i\n"), m_PID);
		}
		else
		{
			_tprintf(TEXT("Failed to attach to process.  hr = %#x\n"), hr);
			return;
		}

		if(m_bSetAttachCompleteEvent)
		{
			// Set the event that indicates to whatever was handling the exception, that they should pass
			// the exception on to us
			if(0 == SetEvent(m_hPMAttachCompleteEvent))
				_tprintf(TEXT("Failed to set post mortem completed attaching event\n"));
		}
	}
	else
		return;

	m_bSessionFinished = false;
	m_bKillSession = false;
	// Main debug loop
	while(1)
	{
		// Should return E_UNEXPECTED when process exits, but maybe also if there is an outstanding request for input
		hr = m_pIDebugControl->WaitForEvent(0, INFINITE);
		if(FAILED(hr))
		{
			if(E_UNEXPECTED == hr)
				_tprintf(TEXT("WaitForEvent returned because there is an outstanding request for input, or none of the targets could generate events.  hr = %#x\n"), hr);
			else if(E_PENDING == hr)
				_tprintf(TEXT("WaitForEvent returned because an exit interrupt was issued. The target is not available.  hr = %#x\n"), hr);
			else
				_tprintf(TEXT("WaitForEvent returned an error.  hr = %#x\n"), hr);
			break;
		}

		if(0 == m_PID)
		{
			ULONG64 lProcHandle = 0;
			hr = m_pIDebugSystemObjects->GetCurrentProcessHandle(&lProcHandle);
			if(FAILED(hr))
			{
				_tprintf(TEXT("Call to IDebugSystemObjects->GetCurrentProcessHandle failed.  hr = %#x\n"), hr);
			}
			else
			{
				m_PID = ::GetProcessId((HANDLE)lProcHandle);
			}
		}

		// If we are writing a crash dump on exception and a crash file comment hasn't been specified,
		// then write the command line as the comment
		if( (NULL != m_pcOutputDir) && (NULL == m_pcCrashFileComment) )
		{
			m_pcCrashFileComment = GetCommandLine();
			m_poDebugEventCallbacks->SetCrashFileComment(m_pcCrashFileComment);
		}

		// Check for an exception
		if(m_poDebugEventCallbacks->GetExceptionOccurred())
		{
			m_poDebugEventCallbacks->SetExceptionOccurred(false);
			// A 2nd chance exception occurred, so stop debugging and terminate the process.  Even if
			// we just attached to this process, there is no recovery from this for the process.
			hr = m_pIDebugClient->EndSession(DEBUG_END_ACTIVE_TERMINATE);
			if(FAILED(hr))
			{
				_tprintf(TEXT("Failed to end session.  hr = %#x\n"), hr);
			}
			// Tear down our debugger
			UninitialiseDbgEngClient();
			break;
		}

		// Check for process exit
		if(m_poDebugEventCallbacks->HasTargetExited())
		{
			hr = m_pIDebugClient->DetachProcesses();
			// Tear down our debugger
			UninitialiseDbgEngClient();	
			break;
		}

		// Check if requested to kill session
		if(m_bKillSession)
		{
			m_bKillSession = false;
			HANDLE hnd = NULL;
			if(0 != m_PID)
				hnd = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_PID);
			if(NULL == hnd)
			{
				// The process we have started has exited, but it spawned other processes, so
				// we detach from these
				hr = m_pIDebugClient->DetachProcesses();
				if(FAILED(hr))
				{
					_tprintf(TEXT("Failed to detach from debugee's spawned processes.  hr = %#x\n"), hr);
				}
			}
			else
			{
				// Stop debugging and terminate the process.
				hr = m_pIDebugClient->EndSession(DEBUG_END_ACTIVE_TERMINATE);
				if(FAILED(hr))
				{
					_tprintf(TEXT("Failed to kill session.  hr = %#x\n"), hr);
				}
				CloseHandle(hnd);
			}
				
			// Tear down our debugger
			UninitialiseDbgEngClient();
			break;
		}

		hr = m_pIDebugControl->SetExecutionStatus(DEBUG_STATUS_GO);
		if(FAILED(hr))
		{
			_tprintf(TEXT("Failed to set execution status.  hr = %#x\n"), hr);
		}
	}
	// Flag that our debugging session has finished
	m_bSessionFinished = true;
	
	// Set the event indicating we are done
	if(0 != m_hSessionFinished)
		SetEvent(m_hSessionFinished);

	return;
}

bool DBGSession::HasProcessExited()
{
	// The session may be active, but the target process may have actually exited (this happens if the 
	// target process spawns other processes)
	//HANDLE hnd = NULL;
	//if(0 != m_PID)
	//	hnd = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_PID);
	//if(NULL == hnd)
	//{
	//	// The target process has ended
	//	KillSession();
	//}
	//else
	//	CloseHandle(hnd);

	return m_bSessionFinished;
}

void DBGSession::KillSession()
{
	m_bKillSession = true;
	HRESULT hr;
	int iTryCount = 0;
	
	do
	{
		hr = m_pIDebugControl->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
		if(SUCCEEDED(hr))
			break;
		else
			Sleep(100);

	} while(iTryCount++ < 10);
	
	if(FAILED(hr))
	{
		_tprintf(TEXT("Failed to set interrupt.  hr = %#x\n"), hr);
	}

	iTryCount = 0;
	if(SUCCEEDED(hr))
		while(!m_bSessionFinished && (iTryCount++ < 50))
			Sleep(100);

}

TCHAR* DBGSession::ExecuteCommand(TCHAR* pcCommand)
{
	return NULL;
}