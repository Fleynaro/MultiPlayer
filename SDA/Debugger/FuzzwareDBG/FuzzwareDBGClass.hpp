
#if _MSC_VER > 1000
#pragma once
#endif

#ifndef __FUZZWAREDBGCLASS_HPP_
#define __FUZZWAREDBGCLASS_HPP_

#include "unknwn.h"
#include "objbase.h"
#include "FuzzwareDBG.hpp"

//const GUID CLSID_FuzzwareDBGClass ={0x8C9991FE, 0x3D7A,0x4f0b,{0xA6,0x2A,0x0E,0xBD,0x08,0xB0,0x72,0x5F}}; 

extern HANDLE g_hEventShutdown;
extern void LockModule();
extern void UnlockModule();

class FuzzwareDBGClass : public IClassFactory
{
	LONG m_cRef;
public:
	STDMETHODIMP QueryInterface(REFIID riid, void **ppv)
	{
		*ppv = 0;
		if(IID_IUnknown == riid)
			*ppv = static_cast<IUnknown*>(this);
		else if(IID_IClassFactory == riid)
			*ppv = static_cast<IClassFactory*>(this);
		else
			return E_NOINTERFACE;
		static_cast<IUnknown*>(*ppv)->AddRef();
		return S_OK;
	}

	STDMETHODIMP_(ULONG) AddRef(void)
	{
		return 2;
		/*if(0 == m_cRef)
			LockModule();
		return InterlockedIncrement(&m_cRef);*/
	}

	STDMETHODIMP_(ULONG) Release(void)
	{
		return 1;
		/*LONG res = InterlockedDecrement(&m_cRef);
		if(0 == res)
		{
			UnlockModule();
			delete this;
		}
		return res;*/
	}

	STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void **ppv)
	{
		*ppv = 0;
		if(pUnkOuter != 0)	// We don't support aggregation
			return CLASS_E_NOAGGREGATION;

		// Create a new instance of our class
		FuzzwareDBG *p = new FuzzwareDBG();
		if(0 == p)
			return E_OUTOFMEMORY;

		// Increment reference count by one
		p->AddRef();
		// Store the resultant interface pointer into *ppv
		HRESULT hr = p->QueryInterface(riid, ppv);
		// Decrement reference count by one, which will delete the object if QI fails
		p->Release();
		// Return result of FuzzwareDBG::QueryInterface
		return hr;
	}

	STDMETHODIMP LockServer(BOOL Block)
	{
		if(Block)
			LockModule();
		else
			UnlockModule();
		return S_OK;
		//return CoLockObjectExternal(static_cast<IUnknown*>(this), Block, TRUE);
	}
};

#endif __FUZZWAREDBGCLASS_HPP_