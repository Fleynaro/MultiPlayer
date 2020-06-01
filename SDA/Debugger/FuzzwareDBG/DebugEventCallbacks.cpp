
#include "DebugEventCallbacks.hpp"
#include <stdio.h>
#include <strsafe.h>
#include "Common.h"

/*
* Constructor.  If pcBaseOutputDir is NULL then exceptions will not cause crash dumps to be written.
*/
STDMETHODCALLTYPE DebugEventCallbacks::DebugEventCallbacks(IDebugClient5* pIDebugClient, IDebugSystemObjects4* pIDebugSystemObjects, TCHAR* pcBaseOutputDir)
{
	m_RefCount = 0;
	
	m_pIDebugSystemObjects = pIDebugSystemObjects;
	m_pIDebugClient = pIDebugClient;

	m_poOutputExceptionWriter = NULL;
	if(NULL != pcBaseOutputDir)
		m_poOutputExceptionWriter = new OutputExceptionWriter(m_pIDebugClient, pcBaseOutputDir);

	m_CrashFileComment = NULL;
	m_bFirstEventOccurred = false;
	m_bExceptionOccurred = false;
	m_bTargetExited = false;
}

STDMETHODCALLTYPE DebugEventCallbacks::~DebugEventCallbacks()
{
	if(NULL != m_poOutputExceptionWriter)
		delete m_poOutputExceptionWriter;
}

void STDMETHODCALLTYPE DebugEventCallbacks::SetCrashFileComment(TCHAR* pcComment)
{
	if(NULL != m_CrashFileComment)
		free(m_CrashFileComment);

	if(NULL == pcComment)
	{
		m_CrashFileComment = TEXT("");
		return;
	}

	// Copy the passed in string
	m_CrashFileComment = CopyString(pcComment);
	/*m_CrashFileComment = (TCHAR*)malloc( (_tcslen(pcComment) + 1) * sizeof(pcComment) );
	StringCchCopy(m_CrashFileComment, (_tcslen(pcComment) + 1), pcComment);*/
}

bool STDMETHODCALLTYPE DebugEventCallbacks::GetExceptionOccurred()
{
	return m_bExceptionOccurred;
}

void STDMETHODCALLTYPE DebugEventCallbacks::SetExceptionOccurred(bool bVal)
{
	m_bExceptionOccurred = bVal;
}

bool STDMETHODCALLTYPE DebugEventCallbacks::HasTargetExited()
{
	return m_bTargetExited;
}

/*
* A process can create child processes which we get the exit process event for, we
* need to be able to reset that the target has exited if it wasn't the parent process
*/
void STDMETHODCALLTYPE DebugEventCallbacks::ResetTargetExited()
{
	m_bTargetExited = false;
}

void STDMETHODCALLTYPE DebugEventCallbacks::IgnoreFirstEvent()
{
	m_bFirstEventOccurred = true;
}

ULONG STDMETHODCALLTYPE DebugEventCallbacks::AddRef()
{
	//this->poExtExtension->Out("AddRef called\n");
	return m_RefCount++;
}

ULONG STDMETHODCALLTYPE DebugEventCallbacks::Release()
{
	//this->poExtExtension->Out("Release called\n");
	return --m_RefCount;
}


HRESULT STDMETHODCALLTYPE DebugEventCallbacks::GetInterestMask(PULONG Mask)
{
	// Interested in everything
	*Mask = DEBUG_EVENT_BREAKPOINT |
			DEBUG_EVENT_EXCEPTION |
			DEBUG_EVENT_CREATE_THREAD |
			DEBUG_EVENT_EXIT_THREAD |
			DEBUG_EVENT_CREATE_PROCESS |
			DEBUG_EVENT_EXIT_PROCESS |
			DEBUG_EVENT_LOAD_MODULE |
			DEBUG_EVENT_UNLOAD_MODULE |
			DEBUG_EVENT_SYSTEM_ERROR |
			DEBUG_EVENT_SESSION_STATUS |
			DEBUG_EVENT_CHANGE_DEBUGGEE_STATE |
			DEBUG_EVENT_CHANGE_ENGINE_STATE |
			DEBUG_EVENT_CHANGE_SYMBOL_STATE;
	
	return S_OK;
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::Breakpoint(PDEBUG_BREAKPOINT Bp)
{
	if(!m_bFirstEventOccurred)
	{
		m_bFirstEventOccurred = true;
		return DEBUG_STATUS_BREAK;
	}

	return DebugBaseEventCallbacks::Breakpoint(Bp);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::Exception(PEXCEPTION_RECORD64 Exception, ULONG FirstChance)
{
	TCHAR* pcExceptionAdd = m_poOutputExceptionWriter->GetSymbolicAddress(Exception->ExceptionAddress);
		
	if(FirstChance != 0)
	{
		_tprintf(TEXT("Identified a first chance exception at %s\n"), pcExceptionAdd);
		free(pcExceptionAdd);
		return DEBUG_STATUS_GO;
	}
	else
	{
		_tprintf(TEXT("Identified a second chance exception at %s\n"), pcExceptionAdd);
		//_tprintf(TEXT("Second chance exception occurred at %#0x\n"), Exception->ExceptionAddress);
		m_bExceptionOccurred = true;

		if(NULL != m_poOutputExceptionWriter)
			m_poOutputExceptionWriter->WriteException(Exception, m_CrashFileComment);

		free(pcExceptionAdd);
		return DEBUG_STATUS_BREAK;
	}

	//return DEBUG_STATUS_IGNORE_EVENT;
	return DebugBaseEventCallbacks::Exception(Exception, FirstChance);
	
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::ChangeDebuggeeState(ULONG Flags, ULONG64 Argument)
{
	return DebugBaseEventCallbacks::ChangeDebuggeeState(Flags, Argument);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::ChangeEngineState(ULONG Flags, ULONG64 Argument)
{
	return DebugBaseEventCallbacks::ChangeEngineState(Flags, Argument);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::ChangeSymbolState(ULONG Flags, ULONG64 Argument)
{
	return DebugBaseEventCallbacks::ChangeSymbolState(Flags, Argument);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::CreateProcess(
		ULONG64 ImageFileHandle,
        ULONG64 Handle,
        ULONG64 BaseOffset,
        ULONG ModuleSize,
        PCSTR ModuleName,
        PCSTR ImageName,
        ULONG CheckSum,
        ULONG TimeDateStamp,
        ULONG64 InitialThreadHandle,
        ULONG64 ThreadDataOffset,
        ULONG64 StartOffset)
{
	if(!m_bFirstEventOccurred)
	{
		m_bFirstEventOccurred = true;
		return DEBUG_STATUS_BREAK;
	}

	return DebugBaseEventCallbacks::CreateProcess(
		ImageFileHandle,
        Handle,
        BaseOffset,
        ModuleSize,
        ModuleName,
        ImageName,
        CheckSum,
        TimeDateStamp,
        InitialThreadHandle,
        ThreadDataOffset,
        StartOffset);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::CreateThread(ULONG64 Handle, ULONG64 DataOffset, ULONG64 StartOffset)
{
	if(!m_bFirstEventOccurred)
	{
		m_bFirstEventOccurred = true;
		return DEBUG_STATUS_BREAK;
	}

	return DebugBaseEventCallbacks::CreateThread(Handle, DataOffset, StartOffset);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::ExitProcess(ULONG ExitCode)
{
	if(!m_bFirstEventOccurred)
	{
		m_bFirstEventOccurred = true;
		return DEBUG_STATUS_BREAK;
	}

	ULONG ulCount = 0;
	HRESULT hr = m_pIDebugSystemObjects->GetNumberProcesses(&ulCount);
	if(SUCCEEDED(hr) && (1 == ulCount))
	{
		m_bTargetExited = true;
		return DEBUG_STATUS_BREAK;
	}

	return DebugBaseEventCallbacks::ExitProcess(ExitCode);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::ExitThread(ULONG ExitCode)
{
	if(!m_bFirstEventOccurred)
	{
		m_bFirstEventOccurred = true;
		return DEBUG_STATUS_BREAK;
	}

	return DebugBaseEventCallbacks::ExitThread(ExitCode);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::LoadModule(ULONG64 ImageFileHandle, ULONG64 BaseOffset, ULONG ModuleSize, PCSTR ModuleName, PCSTR ImageName, ULONG CheckSum, ULONG TimeDateStamp)
{
	if(!m_bFirstEventOccurred)
	{
		m_bFirstEventOccurred = true;
		return DEBUG_STATUS_BREAK;
	}

	return DebugBaseEventCallbacks::LoadModule(ImageFileHandle, BaseOffset, ModuleSize, ModuleName, ImageName, CheckSum, TimeDateStamp);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::SessionStatus(ULONG Status)
{
	return DebugBaseEventCallbacks::SessionStatus(Status);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::SystemError(ULONG Error, ULONG Level)
{
	return DebugBaseEventCallbacks::SystemError(Error, Level);
}

HRESULT STDMETHODCALLTYPE DebugEventCallbacks::UnloadModule(PCSTR ImageBaseName, ULONG64 BaseOffset)
{
	if(!m_bFirstEventOccurred)
	{
		m_bFirstEventOccurred = true;
		return DEBUG_STATUS_BREAK;
	}

	return DebugBaseEventCallbacks::UnloadModule(ImageBaseName, BaseOffset);
}