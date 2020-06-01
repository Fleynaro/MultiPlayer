
#if _MSC_VER > 1000
#pragma once
#endif

#ifndef __COMMON_h_
#define __COMMON_h_

#include "windows.h"
#include <tchar.h>
#include <strsafe.h>

// Global event to keep process alive
extern HANDLE g_hEventShutdown;
void LockModule();
void UnlockModule();

/*
* Returns a copy of the (null-terminated) string passed in.  Caller needs to free returned string.
*/
TCHAR* CopyString(const TCHAR* pcOriginal);


#endif __COMMON_h_