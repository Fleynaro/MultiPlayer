
#include "FileSysDirectory.hpp"
#include "windows.h"
#include <stdlib.h>
#include <strsafe.h>
#include <io.h>
#include <string.h>
#include <direct.h>
#include <errno.h>
#include "Common.h"

/*
* Creates a new File System Directory object.
* BasePath: The base path to use.  If this is a relative path it will
*			be expanded to a full path, using the current working 
*			directory.
* If the BasePath cannot be set the directory value is "", this
* should be checked for.
*/
FileSysDirectory::FileSysDirectory(TCHAR* BasePath)
{
	m_pcBasePath = TEXT("");

	// This could allocate a new TCHAR*, which we have to free
	m_pcBasePath = _tfullpath(NULL, BasePath, 0);

	if(m_pcBasePath == BasePath)
	{
		// A new string wasn't allocated so copy this one
		m_pcBasePath = CopyString(BasePath);
		/*m_pcBasePath = (TCHAR*)malloc( (_tcslen(BasePath) + 1) * sizeof(TCHAR) );
		if(NULL != m_pcBasePath)
			StringCchCopy(m_pcBasePath, (_tcslen(BasePath) + 1), BasePath);*/
	}

	// Make sure the last character is always a slash
	if(NULL != m_pcBasePath)
	{
		if( !((m_pcBasePath[_tcslen(m_pcBasePath) - 1] == '\\') ||
			(m_pcBasePath[_tcslen(m_pcBasePath) - 1] == '/')) )
		{
			Append(TEXT("\\"));
		}
	}
}

/*
* Desctructor for FileSysDirectory
*/
FileSysDirectory::~FileSysDirectory()
{
	if(NULL != m_pcBasePath)
		free(m_pcBasePath);
}

/*
* Appends a directory to the current directory value.
*/
void FileSysDirectory::Append(const TCHAR* Dir)
{
	if(NULL == Dir)
		return;
	
	bool bAddTrailingSlash = true;
	if( (Dir[_tcslen(Dir) - 1] == '\\') ||
		(Dir[_tcslen(Dir) - 1] == '/') )
		bAddTrailingSlash = false;

	size_t szCurrentLen = _tcslen(m_pcBasePath) + 1;
	size_t szAddLen = _tcslen(Dir) + (bAddTrailingSlash?1:0);	// Add an extra char if we need to add trailing slash
	m_pcBasePath = (TCHAR*)realloc(m_pcBasePath, (szCurrentLen + szAddLen) * sizeof(TCHAR));
	if(NULL != m_pcBasePath)
	{
		size_t szNewLength = szCurrentLen + szAddLen;
		StringCchCat(m_pcBasePath, szNewLength, Dir);
		if(bAddTrailingSlash)
			StringCchCat(m_pcBasePath, szNewLength, TEXT("\\"));
	}
}

/*
* Checks whether or not the current directory value exists
*/
bool FileSysDirectory::Exists()
{
	if(0 != _access_s(m_pcBasePath, 0))
		return false;

	return true;
}

/*
* Creates the current directory value
*/
bool FileSysDirectory::Create()
{
	TCHAR* pcSlash = m_pcBasePath;
	// From left to right, find each slash and make each directory in the path
	do
	{
		pcSlash = _tcspbrk(pcSlash, TEXT("\\/"));
		
		if(NULL != pcSlash)
		{
			// We found a '\' or '/'
			size_t szCharCount = pcSlash - m_pcBasePath + 1;
			// Copy the substring
			TCHAR* pcPartPath = (TCHAR*)malloc( (szCharCount + 1) * sizeof(TCHAR));
			if(NULL != pcPartPath)
			{
				// This will only do a partial copy up until the size of the szCharCount
				_tcsncpy_s(pcPartPath, szCharCount + 1, m_pcBasePath, szCharCount);
				pcPartPath[szCharCount] = 0;

				// Check if the path exists, if not create it
				if(-1 == _mkdir(pcPartPath))
				{
					// The dir might already exist (which is ok), or the Path was not found (which is an error)
					if(ENOENT == errno)
					{
						free(pcPartPath);
						return false;
					}
				}
				free(pcPartPath);
			}
		}
	}
	while(NULL != pcSlash++);

	return true;
}

/*
* Returns the current directory value
*/
const TCHAR* FileSysDirectory::Value()
{
	return m_pcBasePath;
}

/*
* Copy the directory value to another FileSysDirectory object
*/
FileSysDirectory* FileSysDirectory::Copy()
{
	return new FileSysDirectory(m_pcBasePath);
}