
#include "OutputExceptionWriter.hpp"
#include <tchar.h>
#include <stdio.h>
#include "dbgeng.h"
#include <strsafe.h>
#include <time.h>
#include "Common.h"

const TCHAR* CRASH_DUMP_FILENAME = TEXT("Memory.dmp");
const TCHAR* CRASH_LOG_FILENAME = TEXT("CrashLog.txt");
const TCHAR* DEFAULT_EXE_NAME = TEXT("exe");

OutputExceptionWriter::OutputExceptionWriter(IDebugClient5* pIDebugClient, TCHAR* BaseDir)
{
	m_pIDebugClient = pIDebugClient;

	m_poOutputBaseDir = new FileSysDirectory(BaseDir);

	HRESULT hr;
	hr = DebugCreate(IID_IDebugSymbols3, (PVOID*)(&m_pIDebugSymbols));
	if(S_OK != hr)
	{
		_tprintf(TEXT("Could not create IID_IDebugSymbols3.  hr = %#x\n"), hr);
	}

	m_pcExeName = NULL;
}

OutputExceptionWriter::~OutputExceptionWriter()
{
	free(m_pcExeName);
	delete m_poOutputBaseDir;

	m_pIDebugSymbols->Release();
}

// Returns a copy of the current process executable name.  The caller needs to free this string.
//TCHAR* OutputExceptionWriter::GetExeName()
//{
//	SetExeName();
//
//	if(NULL != m_pcExeName)
//		return CopyString(m_pcExeName);
//
//	return NULL;
//}

void OutputExceptionWriter::SetExeName()
{
	// Get the current process exe name
	IDebugSystemObjects4* pIDebugSystemObjects = NULL;
	HRESULT hr = DebugCreate(IID_IDebugSystemObjects4, (PVOID*)(&pIDebugSystemObjects));
	if(SUCCEEDED(hr))
	{
		ULONG ulExeSize = 0;
		hr = pIDebugSystemObjects->GetCurrentProcessExecutableName(m_pcExeName, 0, &ulExeSize);
		m_pcExeName = (TCHAR*)malloc((ulExeSize + 1) * sizeof(TCHAR));
		if(NULL != m_pcExeName)
		{
			hr = pIDebugSystemObjects->GetCurrentProcessExecutableName(m_pcExeName, ulExeSize + 1, &ulExeSize);
			if(FAILED(hr))
			{
				_tprintf(TEXT("Call to IDebugSystemObjects4->GetCurrentProcessExecutableName failed, hr = %#x.\n"), hr);
				free(m_pcExeName);
				m_pcExeName = NULL;
			}
			else
			{
				// GetCurrentProcessExecutableName can return the fully qualified path, strip to get just the exe name
				TCHAR* pcLastSlash = _tcsrchr(m_pcExeName, '\\');
				if(NULL == pcLastSlash)
					pcLastSlash = _tcsrchr(m_pcExeName, '/');

				if(NULL != pcLastSlash)
				{
					TCHAR* pcShortExeName = CopyString(pcLastSlash + 1);
					free(m_pcExeName);
					m_pcExeName = pcShortExeName;
				}
			}
		}
		else
		{
			_tprintf(TEXT("Out of memory.\n"));
			return;
		}
		pIDebugSystemObjects->Release();
	}
	else
	{
		_tprintf(TEXT("Could not create IID_IDebugSystem4.  hr = %#x\n"), hr);
	}
	// On failure, set to a default value
	if(NULL == m_pcExeName)
	{
		m_pcExeName = (TCHAR*)malloc((_tcslen(DEFAULT_EXE_NAME) + 1) * sizeof(TCHAR));
		if(NULL != m_pcExeName)
		{
			hr = StringCchCopy(m_pcExeName, (_tcslen(DEFAULT_EXE_NAME) + 1), DEFAULT_EXE_NAME);
			if(FAILED(hr))
			{
				_tprintf(TEXT("Call to StringCchCopy failed, hr = %#x.\n"), hr);
				free(m_pcExeName);
				m_pcExeName = NULL;
			}
		}
		else
		{
			_tprintf(TEXT("Out of memory.\n"));
			return;
		}
	}
}

const TCHAR* GetExceptionCodeString(PEXCEPTION_RECORD64 Exception)
{
	if(EXCEPTION_ACCESS_VIOLATION == Exception->ExceptionCode)
	{
		// Get whether it was a read, write or DEP violation
		if( (NULL != Exception->ExceptionInformation) && (2 == Exception->NumberParameters) )
		{
			// Read AV
			if(0 == Exception->ExceptionInformation[0])
				return TEXT("Read Access Violation");
			// Write AV
			else if(1 == Exception->ExceptionInformation[0])
				return TEXT("Write Access Violation");
			// DEP AV
			else if(8 == Exception->ExceptionInformation[0])
				return TEXT("DEP Access Violation");
			// Unknown (this should never be hit)
			else
				return TEXT("Access Violation");
		}
	}
	else if(EXCEPTION_ARRAY_BOUNDS_EXCEEDED == Exception->ExceptionCode)
	{
		return TEXT("Arrays Bounds Exceeded");
	}
	else if(EXCEPTION_BREAKPOINT == Exception->ExceptionCode)
	{
		return TEXT("Breakpoint");
	}
	else if(EXCEPTION_DATATYPE_MISALIGNMENT == Exception->ExceptionCode)
	{
		return TEXT("DataType Misalignment");
	}
	else if(EXCEPTION_FLT_DENORMAL_OPERAND == Exception->ExceptionCode)
	{
		return TEXT("FLT Denormal Operand");
	}
	else if(EXCEPTION_FLT_DIVIDE_BY_ZERO == Exception->ExceptionCode)
	{
		return TEXT("FLT Divide By Zero");
	}
	else if(EXCEPTION_FLT_INEXACT_RESULT == Exception->ExceptionCode)
	{
		return TEXT("FLT Inexact Result");
	}
	else if(EXCEPTION_FLT_INVALID_OPERATION == Exception->ExceptionCode)
	{
		return TEXT("FLT Invalid Operation");
	}
	else if(EXCEPTION_FLT_OVERFLOW == Exception->ExceptionCode)
	{
		return TEXT("FLT Overflow");
	}
	else if(EXCEPTION_FLT_STACK_CHECK == Exception->ExceptionCode)
	{
		return TEXT("FLT StackCheck");
	}
	else if(EXCEPTION_FLT_UNDERFLOW == Exception->ExceptionCode)
	{
		return TEXT("FLT Underflow");
	}
	else if(EXCEPTION_ILLEGAL_INSTRUCTION == Exception->ExceptionCode)
	{
		return TEXT("Illegal Instruction");
	}
	else if(EXCEPTION_IN_PAGE_ERROR == Exception->ExceptionCode)
	{
		return TEXT("In Page Error");
	}
	else if(EXCEPTION_INT_DIVIDE_BY_ZERO == Exception->ExceptionCode)
	{
		return TEXT("INT Divide By Zero");
	}
	else if(EXCEPTION_INT_OVERFLOW == Exception->ExceptionCode)
	{
		return TEXT("INT Overflow");
	}
	else if(EXCEPTION_INVALID_DISPOSITION == Exception->ExceptionCode)
	{
		return TEXT("Invalid Disposition");
	}
	else if(EXCEPTION_NONCONTINUABLE_EXCEPTION == Exception->ExceptionCode)
	{
		return TEXT("Noncontinuable Exception");
	}
	else if(EXCEPTION_PRIV_INSTRUCTION == Exception->ExceptionCode)
	{
		return TEXT("Privileged Instruction");
	}
	else if(EXCEPTION_SINGLE_STEP == Exception->ExceptionCode)
	{
		return TEXT("Single Step");
	}
	else if(EXCEPTION_STACK_OVERFLOW == Exception->ExceptionCode)
	{
		return TEXT("Stack Exhaustion");
	}

	return TEXT("Unknown");
}

/*
*  Gets the symbolic address from a numeric address.  Caller needs to free returned string.
*/
TCHAR* OutputExceptionWriter::GetSymbolicAddress(DWORD64 ExceptionAddress)
{
	HRESULT hr;
	size_t szSymbolNameBufLen = MAX_PATH;
	TCHAR* pcSymbolName = NULL;
	ULONG ulSymNameLen = 0;
	ULONG64 ul64Displacement = 0;
	// Get string containing name of module and symbol, may have to repeat if buffer is not big enough
	do
	{
		pcSymbolName = (TCHAR*)malloc( szSymbolNameBufLen * sizeof(TCHAR) );
		if(NULL == pcSymbolName)
		{
			_tprintf(TEXT("Out of memory error.\n"));
			return NULL;
		}
		// It seems GetNameByOffset may return just the module name and offset to the address
		// in the module e.g. modulename+Displacement, rather than modulename!function+Displacement
		hr = m_pIDebugSymbols->GetNameByOffsetT(ExceptionAddress, pcSymbolName, (ULONG)szSymbolNameBufLen, &ulSymNameLen, &ul64Displacement);
		if(E_FAIL == hr)
		{
			_tprintf(TEXT("Call to IDebugSymbols->GetNameByOffset failed, hr = %#x.  Failed to get symbol for exception.\n"), hr);
			// Use the exception address as the symbol name
			//_i64tot_s(ExceptionAddress, pcSymbolName, ulSymbolNameBufLen, 10);
			_stprintf_s(pcSymbolName, szSymbolNameBufLen, "%#x", ExceptionAddress);
			return pcSymbolName;
		}
		if(S_FALSE == hr)
		{
			free(pcSymbolName);
			szSymbolNameBufLen = 2 * szSymbolNameBufLen;
		}
		// If hr == S_OK we'll break out
	} while(S_FALSE == hr);
	
	// Get offset from known symbol as a string
	TCHAR* pcDisplacment = (TCHAR*)malloc( 128 * sizeof(TCHAR));
	if(NULL == pcDisplacment)
	{
		_tprintf(TEXT("Out of memory error.\n"));
		return NULL;
	}
	// Get as a hex string
	//_i64tot_s(ul64Displacement, pcDisplacment, 128, 10);
	_stprintf_s(pcDisplacment, 128, "%#x", ul64Displacement);

	// Combine symbol name and offset
	if(szSymbolNameBufLen <= (ulSymNameLen + _tcslen(pcDisplacment) + 1))	// need room for '+' too
	{
		szSymbolNameBufLen = (ulSymNameLen + _tcslen(pcDisplacment) + 1);
		pcSymbolName = (TCHAR*)realloc(pcSymbolName, (szSymbolNameBufLen + 1) * sizeof(TCHAR) );
		if(NULL == pcSymbolName)
		{
			_tprintf(TEXT("Out of memory error.\n"));
			return NULL;
		}
	}
	StringCchCat(pcSymbolName, szSymbolNameBufLen, TEXT("+"));
	StringCchCat(pcSymbolName, szSymbolNameBufLen, pcDisplacment);

	free(pcDisplacment);

	return pcSymbolName;
}

/*
* Writes the time and comment to the crash log in the specified directory.
*/
void OutputExceptionWriter::LogCrashEvent(FileSysDirectory* poOutputDir, TCHAR* pcComment)
{
	// Create the crash log file name
	const TCHAR* pcDir = poOutputDir->Value();
	size_t cbCrashLogPath = _tcslen(pcDir) + _tcslen(CRASH_LOG_FILENAME) + 1;
	TCHAR* pcCrashLogPath = (TCHAR*)malloc( cbCrashLogPath * sizeof(TCHAR) );
	if(NULL == pcCrashLogPath)
	{
		_tprintf(TEXT("Out of memory error.\n"));
		return;
	}
	StringCchCopy(pcCrashLogPath, cbCrashLogPath, pcDir);
	StringCchCat(pcCrashLogPath, cbCrashLogPath, CRASH_LOG_FILENAME);

	// Create string to write to file
	size_t szCrashLogEntry = MAX_PATH;
	TCHAR* pcCrashLogEntry = (TCHAR*)malloc( szCrashLogEntry * sizeof(TCHAR) );
	if(NULL == pcCrashLogEntry)
	{
		_tprintf(TEXT("Out of memory error.\n"));
		return;
	}

	// Write date and time
	struct tm newtime;
    __time64_t long_time;
    _time64( &long_time );           // Get time as 64-bit integer.
    // Convert to local time.
    _localtime64_s(&newtime, &long_time );

	// Assume MAX_PATH is enough to hold the date
	size_t szTime = _tcsftime(pcCrashLogEntry, szCrashLogEntry, TEXT("%x %X - "), &newtime);

	if(NULL == pcComment)
		pcComment = CopyString(TEXT(" "));

	size_t szLogEntry = szTime + _tcslen(pcComment) + _tcslen(TEXT("\n"));	
	if(szCrashLogEntry <= szLogEntry )
	{
		szCrashLogEntry = szLogEntry + 1;
		pcCrashLogEntry = (TCHAR*)realloc(pcCrashLogEntry, (szCrashLogEntry + 1) * sizeof(TCHAR) );
		if(NULL == pcCrashLogEntry)
		{
			_tprintf(TEXT("Out of memory error.\n"));
			return;
		}
	}

	// Append Comment to crash log entry
	StringCchCat(pcCrashLogEntry, szCrashLogEntry, pcComment);
	StringCchCat(pcCrashLogEntry, szCrashLogEntry, TEXT("\n"));

	// Open the file for appending
	FILE* fCrashLogFile;
	errno_t err = _tfopen_s(&fCrashLogFile, pcCrashLogPath, "a+t");
	if(0 != err)
	{
		_tprintf(TEXT("Failed to open crash log '%s', errno = %#x..\n"), pcCrashLogPath, err);
		return;
	}

	// Write to file
	fwrite(pcCrashLogEntry, sizeof(TCHAR), szLogEntry, fCrashLogFile);

	// Close file
	fclose(fCrashLogFile);

	free(pcCrashLogPath);
	free(pcCrashLogEntry);
}

/*
* Writes a crash dump to the specified directory, including comment, but only if the crash
* dump does not already exist.  Also writes an entry to the crash log in that directory,
* noting the time and comment.
*/
bool OutputExceptionWriter::CreateCrashDump(FileSysDirectory* poOutputDir, TCHAR* pcComment)
{
	bool ret = true;
	HRESULT hr;
	if(!poOutputDir->Exists())
	{
		poOutputDir->Create();
		
		// Create the crash dump file name
		const TCHAR* pcDir = poOutputDir->Value();
		size_t cbFullCrashDumpPath = _tcslen(pcDir) + _tcslen(CRASH_DUMP_FILENAME) + 1;
		TCHAR* pcFullCrashDumpPath = (TCHAR*)malloc( cbFullCrashDumpPath * sizeof(TCHAR) );
		if(NULL == pcFullCrashDumpPath)
		{
			_tprintf(TEXT("Out of memory error.\n"));
			return false;
		}
		StringCchCopy(pcFullCrashDumpPath, cbFullCrashDumpPath, pcDir);
		StringCchCat(pcFullCrashDumpPath, cbFullCrashDumpPath, CRASH_DUMP_FILENAME);

		// May add ability to create cab files: DEBUG_FORMAT_WRITE_CAB | DEBUG_FORMAT_CAB_SECONDARY_FILES
		ULONG ulFormatFlags =	DEBUG_FORMAT_USER_SMALL_FULL_MEMORY |
								DEBUG_FORMAT_USER_SMALL_HANDLE_DATA | 
								DEBUG_FORMAT_USER_SMALL_INDIRECT_MEMORY | 
								DEBUG_FORMAT_USER_SMALL_DATA_SEGMENTS |
								DEBUG_FORMAT_USER_SMALL_PROCESS_THREAD_DATA |
								DEBUG_FORMAT_USER_SMALL_PRIVATE_READ_WRITE_MEMORY |
								DEBUG_FORMAT_USER_SMALL_FULL_MEMORY_INFO |
								DEBUG_FORMAT_USER_SMALL_THREAD_INFO;
		// Flags doesn't like DEBUG_FORMAT_USER_SMALL_CODE_SEGMENTS, or at least combined with DEBUG_FORMAT_USER_SMALL_FULL_MEMORY
		
#ifdef UNICODE
TODO: convert pcFullCrashDumpPath to a PSTR
#endif
		// Write crash dump
		hr = m_pIDebugClient->WriteDumpFile2(pcFullCrashDumpPath, 
											DEBUG_USER_WINDOWS_SMALL_DUMP, 
											ulFormatFlags, 
											pcComment);

		if(SUCCEEDED(hr))
		{
			_tprintf(TEXT("Wrote crash dump to %s.\n"), pcFullCrashDumpPath);
		}
		else
		{
			_tprintf(TEXT("Call to IDebugClient->WriteDumpFile2 failed, hr = %#x.  Failed to write crash dump.\n"), hr);
			ret = false;
		}

		//Cleanup
		free(pcFullCrashDumpPath);
	}

	// Log that this crashed happened
	LogCrashEvent(poOutputDir, pcComment);

	return ret;
}

bool OutputExceptionWriter::WriteException(PEXCEPTION_RECORD64 Exception, TCHAR* pcCrashDumpFileComment)
{
	// Create the base output directory
	if(!m_poOutputBaseDir->Create())
		_tprintf(TEXT("Unable to create directory '%s'\n"), m_poOutputBaseDir->Value());

	// Create the Exception Type directory, if it doesn't exist
	FileSysDirectory* poOutputDir = m_poOutputBaseDir->Copy();	// Copy creates a new FileSysDirectory

	// Append the exe name
	if(NULL == m_pcExeName)
		SetExeName();
	poOutputDir->Append(m_pcExeName);

	// Get the Exception Type to use as a directory name
	const TCHAR* pcExceptionTypeDir = GetExceptionCodeString(Exception);
	poOutputDir->Append(pcExceptionTypeDir);		// No need to free since strings are constant

	if(!poOutputDir->Exists())
		poOutputDir->Create();

	// Get the Symbolic Exception Address to use as a sub directory of the Exception Type
	// directory
	//m_pIDebugSymbols->OutputSymbolByOffset(DEBUG_OUTCTL_THIS_CLIENT, DEBUG_OUTSYM_FORCE_OFFSET | DEBUG_OUTSYM_ALLOW_DISPLACEMENT, Exception->ExceptionAddress);
	TCHAR* pcSymbolName = GetSymbolicAddress(Exception->ExceptionAddress);
	if(NULL == pcSymbolName)
		return false;
	
	// Construct the Symbolic Exception Address.  
	//FileSysDirectory* poSymExceptionAddDir = poExceptionTypeDir->Copy();		// Copy creates a new FileSysDirectory
	poOutputDir->Append(pcSymbolName);
	free(pcSymbolName);
	// Don't create the output dir with the symbolic address, CreateCrashDump will create it if
	// it does not exist, and relies on it not existing to determine whether to create a crash dump

	// If the output directory already exists, do not create the dump file
	// but note the test case
	CreateCrashDump(poOutputDir, pcCrashDumpFileComment);

	// Cleanup
	delete poOutputDir;

	return true;
}
