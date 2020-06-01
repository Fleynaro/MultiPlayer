
#include <stdio.h>
#include <stdlib.h>
#include "Common.h"


/*
* Returns a copy of the (null-terminated) string passed in.  Caller needs to free returned string.
*/
TCHAR* CopyString(const TCHAR* pcOriginal)
{
	if(NULL == pcOriginal)
		return NULL;

	size_t cchSize = _tcslen(pcOriginal) + 1;
	TCHAR* pcCopy = (TCHAR*)malloc( cchSize * sizeof(TCHAR) );
	if(NULL == pcCopy)
		_tprintf(_TEXT("Out of memory.\n"));

	HRESULT hr = StringCchCopy(pcCopy, cchSize, pcOriginal);
	if(FAILED(hr))
		_tprintf(_TEXT("StringCchCopy failed, %#0x\n"), hr);

	return pcCopy;
}