
#if _MSC_VER > 1000
#pragma once
#endif

#ifndef __REGISTRATION_H_
#define __REGISTRATION_H_

#include "windows.h"
#include "olectl.h"
#include "objbase.h"
#include "tchar.h"
#include "Common.h"
#include "FuzzwareDBGClass.hpp"

STDAPI DllUnregisterServer(void);
STDAPI DllRegisterServer(void);
STDAPI RegisterClassObject();

HRESULT RegisterPostMortem(TCHAR* pszCommandLine);
HRESULT UnregisterPostMortem();

#endif __REGISTRATION_H_