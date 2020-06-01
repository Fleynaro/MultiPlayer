
#if _MSC_VER > 1000
#pragma once
#endif

#ifndef __FuzzwareDBG_h_
#define __FuzzwareDBG_h_

#include "windows.h"
#include "oleauto.h"
#include "dbgeng.h"
#include "Common.h"
#include "DebugEventCallbacks.hpp"
#include "IOCallbacks.hpp"
#include "IFuzzwareDBG_h.h"
#include "DBGSession.hpp"

class FuzzwareDBG : public IFuzzwareDBG
{
	LONG m_cRef;				// COM Reference count
	HANDLE m_hWaitForEventThread;	// Handle to thread that waits for debug events	

	DBGSession* m_pDBGSession;	// Class to handle main debugger loop

public:
	FuzzwareDBG();
	~FuzzwareDBG();

	void WaitForSessionToFinish()
	{
		if(NULL != m_hWaitForEventThread)
		{
			// See if we can access the thread, if so it's probably still going
			if(THREAD_PRIORITY_ERROR_RETURN != GetThreadPriority(m_hWaitForEventThread))
			{
				WaitForSingleObject(m_hWaitForEventThread, INFINITE);
			}
			else
				m_hWaitForEventThread = NULL;
		}
	}

	void SetPMAttachCompleteEvent(HANDLE hEventId)
	{
		m_pDBGSession->SetPMAttachCompleteEvent(hEventId);
	}

	STDMETHODIMP QueryInterface(REFIID riid, void **ppv)
	{
		*ppv = 0;
		if(IID_IUnknown == riid)
			*ppv = static_cast<IUnknown*>(this);
		else if(IID_IFuzzwareDBG == riid)
			*ppv = static_cast<IFuzzwareDBG*>(this);
		else
			return E_NOINTERFACE;
		static_cast<IUnknown*>(*ppv)->AddRef();
		return S_OK;
	}

	STDMETHODIMP_(ULONG) AddRef(void)
	{
		if(0 == m_cRef)
			LockModule();
		return InterlockedIncrement(&m_cRef);
	}

	STDMETHODIMP_(ULONG) Release(void)
	{
		LONG res = InterlockedDecrement(&m_cRef);
		if(0 == res)
		{
			delete this;
			UnlockModule();
		}
		return res;
	}

	HRESULT STDMETHODCALLTYPE SetCrashComment(const BSTR bstrCrashComment);

	HRESULT STDMETHODCALLTYPE SetOutputDir(const BSTR bstrOutputDir);
    
	HRESULT STDMETHODCALLTYPE SetRemoteOptions(const BSTR bstrRemoteOptions);

    HRESULT STDMETHODCALLTYPE CreateProcess(const BSTR bstrCommandLine);
    
    HRESULT STDMETHODCALLTYPE AttachToProcess(unsigned long zProcessId);
    
    HRESULT STDMETHODCALLTYPE RunProcess(unsigned long *pdwProcessId);

    //HRESULT STDMETHODCALLTYPE ExecuteCommand(const BSTR bstrCommand, BSTR *pbstrDebuggerOutput);

	HRESULT STDMETHODCALLTYPE HasProcessExited(boolean *pbProcessExited);

	HRESULT STDMETHODCALLTYPE KillProcess();

};

#endif __FuzzwareDBG_h_