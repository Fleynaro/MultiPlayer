
#include "dbgeng.h"
#include <stdio.h>
#include <tchar.h>
#include "IOCallbacks.hpp"

STDMETHODCALLTYPE IOCallbacks::IOCallbacks()
{
	m_RefCount = 0;
}

ULONG STDMETHODCALLTYPE IOCallbacks::AddRef()
{
	return m_RefCount++;
}

ULONG STDMETHODCALLTYPE IOCallbacks::Release()
{
	return --m_RefCount;
}

/* IDebugInputCallbacks */
HRESULT STDMETHODCALLTYPE IOCallbacks::StartInput(ULONG BufferSize)
{
	return S_OK;
}

HRESULT STDMETHODCALLTYPE IOCallbacks::EndInput()
{
	return S_OK;
}

/* IDebugOutputCallbacks */
HRESULT STDMETHODCALLTYPE IOCallbacks::Output(ULONG Mask, PCSTR Text)
{
	if(DEBUG_OUTPUT_ERROR & Mask)
	{
		//_tprintf(TEXT("FuzzwareDBG ERROR: %s"), Text);
		_tprintf(TEXT("%s"), Text);
	}
	else if(DEBUG_OUTPUT_DEBUGGEE & Mask)
	{
		_tprintf(TEXT("DEBUGGEE OUTPUT: %s"), Text);
	}
	//else
	//	_tprintf(TEXT("%s\n"), Text);
	
	return S_OK;
}

