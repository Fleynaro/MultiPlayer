
#include "windows.h"
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <direct.h>
#include "FuzzwareDBG.hpp"

HRESULT ConvertBSTRtoTCHAR(const BSTR bstrString, TCHAR** pcTCHARString)
{
	// Copy the BSTR to a TCHAR buffer
	DWORD dwCharCount = SysStringLen(bstrString);
	*pcTCHARString = (TCHAR*)malloc((dwCharCount + 1) * sizeof(TCHAR));
	if(NULL == *pcTCHARString)
		return E_OUTOFMEMORY;
#ifdef UNICODE
	HRESULT hr = StringCchCopy(*pcTCHARString, dwCharCount + 1, (TCHAR*)bstrString);
	if(!SUCCEEDED(hr))
		return hr;
#else
	WideCharToMultiByte(CP_ACP, 0, bstrString, -1, *pcTCHARString, (dwCharCount + 1) * sizeof(TCHAR), NULL, NULL);
#endif
	return S_OK;
}

FuzzwareDBG::FuzzwareDBG()
{
	m_cRef = 0;
	m_hWaitForEventThread = NULL;

	m_pDBGSession = new DBGSession();
}

FuzzwareDBG::~FuzzwareDBG()
{
	delete m_pDBGSession;
}

/*
* Sets the comment that will be written to the crash dump file (if a crash occurs)
* and the crash log file.
*/
HRESULT STDMETHODCALLTYPE FuzzwareDBG::SetCrashComment(const BSTR bstrCrashComment)
{
	TCHAR* pcCrashComment = NULL;
	HRESULT hr = ConvertBSTRtoTCHAR(bstrCrashComment, &pcCrashComment);
	if(!SUCCEEDED(hr))
		return hr;
	
	m_pDBGSession->SetCrashFileComment(pcCrashComment);

	free(pcCrashComment);

	return S_OK;
}

/*
* Sets the output directory for storing results.  Default is the current
* working directory (which will most likely be SYSTEM32).  If specified,
* a full path should be used.
*/
HRESULT STDMETHODCALLTYPE FuzzwareDBG::SetOutputDir(const BSTR bstrOutputDir)
{
	TCHAR* pcOutputDir = NULL;
	HRESULT hr = ConvertBSTRtoTCHAR(bstrOutputDir, &pcOutputDir);
	if(!SUCCEEDED(hr))
		return hr;

	m_pDBGSession->SetOutputDir(pcOutputDir);

	free(pcOutputDir);

	return S_OK;
}

/*
* Set the dbgeng remote options string for connecting to a remote debug session.  The string
* is the same argument that the .remote command takes.
*/
HRESULT STDMETHODCALLTYPE FuzzwareDBG::SetRemoteOptions(const BSTR bstrRemoteOptions)
{
	TCHAR* pcRemoteOptions = NULL;
	HRESULT hr = ConvertBSTRtoTCHAR(bstrRemoteOptions, &pcRemoteOptions);
	if(FAILED(hr))
		return hr;

	m_pDBGSession->SetRemoteOptions(pcRemoteOptions);

	free(pcRemoteOptions);

	return S_OK;
}

/*
* Specifies the process to create.  The process is not created until RunProcess is called.
*/
HRESULT STDMETHODCALLTYPE FuzzwareDBG::CreateProcess(const BSTR bstrCommandLine)
{
	// Copy the BSTR to a TCHAR buffer
	TCHAR* pcCommandLine = NULL;
	HRESULT hr = ConvertBSTRtoTCHAR(bstrCommandLine, &pcCommandLine);
	if(FAILED(hr))
		return hr;

	m_pDBGSession->SetCommandLine(pcCommandLine);

	free(pcCommandLine);

	return S_OK;
}

/*
* Specifies the process ID that the debugger will attach to.  The process is not actually 
* attached to until RunProcess is called.
*/
HRESULT STDMETHODCALLTYPE FuzzwareDBG::AttachToProcess(unsigned long zProcessId)
{
	m_pDBGSession->SetProcessIdToAttach(zProcessId);

	return S_OK;
}

/*
* This runs in its own thread and loops until the process being debugged terminates
*/
DWORD WINAPI StartDebugSession(__in LPVOID lpParameter)
{
	DBGSession* pDBGSession = (DBGSession*)lpParameter;

	pDBGSession->RunSession();

	return 0;
}

/*
* Creates a new thread that waits for events from the process being debugged
*/
HRESULT STDMETHODCALLTYPE FuzzwareDBG::RunProcess(unsigned long *pdwProcessId)
{
	// Check to see if we have a running thread already
	if(NULL != m_hWaitForEventThread)
	{
		DWORD dwStatus = 0;
		if(!GetExitCodeThread(m_hWaitForEventThread, &dwStatus))
		{
			_tprintf(TEXT("Call to GetExitCodeThread failed.  GetLastError = %#x\n"), GetLastError());
			// Difficult error handle, bury head in sand...
		}
		else
		{
			// We got the exit status of the worker thread
			if(dwStatus == STILL_ACTIVE)
			{
				// Kill the thread, terminate process being debugged
				TerminateThread(m_hWaitForEventThread, 1);
			}
		}
		m_hWaitForEventThread = NULL;
	}

	m_hWaitForEventThread = ::CreateThread(
		0, 
		0, 
		StartDebugSession,
		m_pDBGSession,
		0,
		NULL);

	if(NULL == m_hWaitForEventThread)
	{
		_tprintf(TEXT("Failed to create thread to wait for debug events.  GetLastError = %#x\n"), GetLastError());
		return E_FAIL;
	}

	int iTryCount = 0;
	// Can't seem to get the process ID until the debugger fully connects.  Wait until this happens, but don't wait forever.
	while((0 == m_pDBGSession->GetProcessId()) && (iTryCount++ < 1000))
		Sleep(10);

	*pdwProcessId = m_pDBGSession->GetProcessId();

	return S_OK;
}

HRESULT STDMETHODCALLTYPE FuzzwareDBG::HasProcessExited(boolean *pbProcessExited)
{
	if(NULL != m_pDBGSession)
	{
		*pbProcessExited = (boolean)m_pDBGSession->HasProcessExited();
		return S_OK;
	}
	return E_FAIL;
}

HRESULT STDMETHODCALLTYPE FuzzwareDBG::KillProcess()
{
	if(NULL != m_pDBGSession)
	{
		m_pDBGSession->KillSession();
		return S_OK;
	}
	return E_FAIL;
}

/*
* Execute a command in the debugger and return the output
*/
//HRESULT STDMETHODCALLTYPE FuzzwareDBG::ExecuteCommand(const BSTR bstrCommand, BSTR *pbstrDebuggerOutput)
//{
//	// Copy the BSTR to a TCHAR buffer
//	DWORD dwCharCount = SysStringLen(bstrCommand);
//	TCHAR* pcCommand = (TCHAR*)malloc((dwCharCount + 1) * sizeof(TCHAR));
//	if(NULL == pcCommand)
//		return E_OUTOFMEMORY;
//#ifdef UNICODE
//	hr = StringCchCopy(pcCommand, dwCharCount, (TCHAR*)bstrCommand);
//	if(!SUCCEEDED(hr))
//		return hr;
//#else
//	WideCharToMultiByte(CP_ACP, 0, bstrCommand, dwCharCount, pcCommand, dwCharCount + 1, NULL, NULL);
//	pcCommand[dwCharCount] = 0;
//#endif
//
//	// Execute the command
//	TCHAR* pcCommandOutput = m_pDBGSession->ExecuteCommand(pcCommand);
//
//	if(NULL != pcCommandOutput)
//	{
//		// Copy the output to an OLECHAR* so we can convert it to a BSTR
//		OLECHAR* polecharCommand = NULL;
//#ifdef UNICODE
//		polecharCommand = pcCommandOutput
//#else
//		dwCharCount = MultiByteToWideChar(CP_ACP, 0, pcCommandOutput, -1, NULL, 0);
//		polecharCommand = (OLECHAR*)malloc( dwCharCount * sizeof(OLECHAR) );
//		if(NULL == polecharCommand)
//			return E_OUTOFMEMORY;
//		MultiByteToWideChar(CP_ACP, 0, pcCommandOutput, -1, polecharCommand, dwCharCount);
//		free(pcCommandOutput);
//#endif
//		*pbstrDebuggerOutput = SysAllocString(polecharCommand);
//		free(polecharCommand);
//	}
//	else
//		*pbstrDebuggerOutput = SysAllocString(OLESTR(""));
//
//	return S_OK;
//}
