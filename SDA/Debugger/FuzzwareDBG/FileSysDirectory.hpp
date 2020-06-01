#if _MSC_VER > 1000
#pragma once
#endif

#ifndef __FILESYSDIRECTORY_HPP_
#define __FILESYSDIRECTORY_HPP_

#include <tchar.h>

class FileSysDirectory
{
	TCHAR* m_pcBasePath;

public:

	/*
	* Creates a new File System Directory object.
	* BasePath: The base path to use.  If this is a relative path it will
	*			be expanded to a full path, using the current working 
	*			directory.
	* If the BasePath cannot be set the directory value is NULL, this
	* be be checked for.
	*/
	FileSysDirectory(TCHAR* BasePath);

	/*
	* Desctructor for FileSysDirectory
	*/
	~FileSysDirectory();

	/*
	* Appends a directory to the current directory value.
	*/
	void Append(const TCHAR* Dir);

	/*
	* Checks whether or not the current directory value exists
	*/
	bool Exists();

	/*
	* Creates the current directory value
	*/
	bool Create();

	/*
	* Returns the current directory value
	*/
	const TCHAR* Value();

	/*
	* Copy the directory value to another FileSysDirectory object
	*/
	FileSysDirectory* Copy();
};


#endif __FILESYSDIRECTORY_HPP_