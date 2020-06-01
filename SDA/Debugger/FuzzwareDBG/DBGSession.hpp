
#if _MSC_VER > 1000
#pragma once
#endif

#ifndef __DBGSession_h_
#define __DBGSession_h_

#include "windows.h"
#include <tchar.h>
#include "dbgeng.h"
#include "DebugEventCallbacks.hpp"
#include "IOCallbacks.hpp"

/*
* This class is used to host the main debugging loop in a separate thread. 
* The main debugger loop needs to be in the same thread that created the
* debugging session.
*/
class DBGSession
{
	IDebugClient5* m_pIDebugClient;					// IDebugClient interface to dbgeng
	IDebugControl4* m_pIDebugControl;				// IDebugControl interface to dbgeng
	IDebugSystemObjects4* m_pIDebugSystemObjects;	// IDebugSystemObjects interface to dbgeng

	DebugEventCallbacks* m_poDebugEventCallbacks;	// Debug event callbacks object
	IOCallbacks* m_poIOCallbacks;					// Debug Input and Output callbacks object
	
	ULONG m_ulSpecificEventFiltersCount;
	ULONG m_ulSpecificExceptionFiltersCount;
	ULONG m_ulArbitraryExceptionFiltersCount;

	TCHAR* m_pcRemoteOptions;
	TCHAR* m_pcCommandLine;
	unsigned long m_PID;
	HANDLE m_hSessionFinished;
	bool m_bSessionFinished;						// Flag indicating session has finised debugging
	bool m_bKillSession;							// Flag indicating session needs to be killed
	bool m_bSetAttachCompleteEvent;
	HANDLE m_hPMAttachCompleteEvent;

	TCHAR* m_pcOutputDir;			// Root directory or results store
	TCHAR* m_pcCrashFileComment;	// The comment to write to the crash file
	bool m_bDebuggingToolsInstalled;

	void SetDbgEngSearchPath();
	void InitialiseDbgEngClient();
	void UninitialiseDbgEngClient();

	void ShowEventFilterHandling();
	void ShowExceptionFilterHandling();

	TCHAR* GetCommandLine();

public:
	DBGSession();
	~DBGSession();

	void SetRemoteOptions(TCHAR* pcRemoteOptions);
	void SetCommandLine(TCHAR* pcCommandLine);
	void SetProcessIdToAttach(unsigned long PID);
	void SetSessionFinishedEvent(HANDLE hSessionFinished);
	void SetPMAttachCompleteEvent(HANDLE hAttachComplete);

	void SetOutputDir(TCHAR* pcOutputDir);
	//void SetCreateCrashDumps(bool bCreateDumps);
	void SetCrashFileComment(TCHAR* pcCrashFileComment);

	unsigned long GetProcessId();
	
	void RunSession();
	bool HasProcessExited();
	void KillSession();

	TCHAR* ExecuteCommand(TCHAR* pcCommand);
};

#endif __DBGSession_h_
