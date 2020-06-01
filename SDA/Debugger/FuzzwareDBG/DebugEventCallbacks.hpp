

#if _MSC_VER > 1000
#pragma once
#endif

#ifndef __DEBUGEVENTCALLBACKS_HPP__
#define __DEBUGEVENTCALLBACKS_HPP__

#include "dbgeng.h"
#include <tchar.h>
#include "OutputExceptionWriter.hpp"

class DebugEventCallbacks : public DebugBaseEventCallbacks
{
	ULONG m_RefCount;
	
	IDebugClient5* m_pIDebugClient;				// IDebugClient interface to dbgeng
	IDebugSystemObjects4* m_pIDebugSystemObjects;
	OutputExceptionWriter* m_poOutputExceptionWriter;

	TCHAR* m_CrashFileComment;		// A comment to add to the crash dump file
	bool m_bFirstEventOccurred;
	bool m_bExceptionOccurred;		// Keeps track of when a 2nd chance exception occurs
	bool m_bTargetExited;

public:
	STDMETHODCALLTYPE DebugEventCallbacks(IDebugClient5* pIDebugClient, IDebugSystemObjects4* pIDebugSystemObjects, TCHAR* pcBaseOutputDir);
	STDMETHODCALLTYPE ~DebugEventCallbacks();

	void STDMETHODCALLTYPE SetCrashFileComment(TCHAR* pcComment);
	bool STDMETHODCALLTYPE GetExceptionOccurred();
	void STDMETHODCALLTYPE SetExceptionOccurred(bool bVal);
	bool STDMETHODCALLTYPE HasTargetExited();
	void STDMETHODCALLTYPE ResetTargetExited();
	void STDMETHODCALLTYPE IgnoreFirstEvent();

	ULONG STDMETHODCALLTYPE AddRef();
	ULONG STDMETHODCALLTYPE Release();

	HRESULT STDMETHODCALLTYPE GetInterestMask(PULONG Mask);
	HRESULT STDMETHODCALLTYPE Breakpoint(PDEBUG_BREAKPOINT Bp);
	HRESULT STDMETHODCALLTYPE Exception(PEXCEPTION_RECORD64 Exception, ULONG FirstChance);
	HRESULT STDMETHODCALLTYPE ChangeDebuggeeState(ULONG Flags, ULONG64 Argument);
	HRESULT STDMETHODCALLTYPE ChangeEngineState(ULONG Flags, ULONG64 Argument);
	HRESULT STDMETHODCALLTYPE ChangeSymbolState(ULONG Flags, ULONG64 Argument);
	HRESULT STDMETHODCALLTYPE CreateProcess(
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
        ULONG64 StartOffset);
	HRESULT STDMETHODCALLTYPE CreateThread(ULONG64 Handle, ULONG64 DataOffset, ULONG64 StartOffset);
	HRESULT STDMETHODCALLTYPE ExitProcess(ULONG ExitCode);
	HRESULT STDMETHODCALLTYPE ExitThread(ULONG ExitCode);
	HRESULT STDMETHODCALLTYPE LoadModule(ULONG64 ImageFileHandle, ULONG64 BaseOffset, ULONG ModuleSize, PCSTR ModuleName, PCSTR ImageName, ULONG CheckSum, ULONG TimeDateStamp);
	HRESULT STDMETHODCALLTYPE SessionStatus(ULONG Status);
	HRESULT STDMETHODCALLTYPE SystemError(ULONG Error, ULONG Level);
	HRESULT STDMETHODCALLTYPE UnloadModule(PCSTR ImageBaseName, ULONG64 BaseOffset);
};




#endif __DEBUGEVENTCALLBACKS_HPP__