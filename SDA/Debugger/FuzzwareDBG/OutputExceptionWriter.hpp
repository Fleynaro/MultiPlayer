#if _MSC_VER > 1000
#pragma once
#endif

#ifndef __OUTPUTEXCEPTIONWRITER_HPP_
#define __OUTPUTEXCEPTIONWRITER_HPP_

#include "windows.h"
#include "dbgeng.h"
#include "tchar.h"
#include "FileSysDirectory.hpp"

class OutputExceptionWriter
{
	IDebugClient5* m_pIDebugClient;				// IDebugClient interface to dbgeng
	IDebugSymbols3* m_pIDebugSymbols;			// IDebugSymbols interface to dbgeng

	FileSysDirectory* m_poOutputBaseDir;		// Base directory for output
	TCHAR* m_pcExeName;							// Name of executable where exception occurred

	void SetExeName();
	void LogCrashEvent(FileSysDirectory* poOutputDir, TCHAR* pcComment);
	bool CreateCrashDump(FileSysDirectory* poOutputDir, TCHAR* pcComment);

public:
	OutputExceptionWriter(IDebugClient5* pIDebugClient, TCHAR* BaseDir);
	~OutputExceptionWriter();

	//TCHAR* GetExeName();
	TCHAR* GetSymbolicAddress(DWORD64 ExceptionAddress);
	bool WriteException(PEXCEPTION_RECORD64 Exception, TCHAR* pcCrashDumpFileComment);
};

#endif __OUTPUTEXCEPTIONWRITER_HPP_