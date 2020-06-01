
#if _MSC_VER > 1000
#pragma once
#endif

#ifndef __IOCALLBACKS_HPP__
#define __IOCALLBACKS_HPP__

#include "dbgeng.h"

class IOCallbacks : public IDebugInputCallbacks, public IDebugOutputCallbacks
{
	ULONG m_RefCount;
public:
    // IUnknown.
    STDMETHOD(QueryInterface)(
        THIS_
        __in REFIID InterfaceId,
        __out PVOID* Interface
        )
    {
        *Interface = NULL;

#if _MSC_VER >= 1100
        if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
            IsEqualIID(InterfaceId, __uuidof(IDebugInputCallbacks)))
#else
        if (IsEqualIID(InterfaceId, IID_IUnknown) ||
            IsEqualIID(InterfaceId, IID_IDebugEventCallbacks))
#endif
        {
            *Interface = (IDebugInputCallbacks *)this;
            AddRef();
            return S_OK;
        }
		else if(IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks)))
		{
            *Interface = (IDebugOutputCallbacks *)this;
            AddRef();
            return S_OK;
        }
        else
        {
            return E_NOINTERFACE;
        }
    }

	ULONG STDMETHODCALLTYPE AddRef();
	ULONG STDMETHODCALLTYPE Release();

	/* IDebugInputCallbacks */
	HRESULT STDMETHODCALLTYPE StartInput(ULONG BufferSize);
	HRESULT STDMETHODCALLTYPE EndInput();
	/* IDebugOutputCallbacks */
	HRESULT STDMETHODCALLTYPE Output(ULONG Mask, PCSTR Text);

	IOCallbacks();
};


#endif __IOCALLBACKS_HPP__