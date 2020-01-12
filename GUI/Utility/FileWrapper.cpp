#include "FileWrapper.h"

using namespace FS;


Directory::itemList Directory::getItems() {
	itemList items;

	WIN32_FIND_DATA findData;
	HANDLE handle = FindFirstFile(
		(getPath() + "\\*").c_str(),
		&findData
	);
	if (handle != INVALID_HANDLE_VALUE) {
		do {
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (findData.cFileName[0] == '.') continue;
				items.push_back(
					std::make_shared<Directory>(
						Directory(getPath() + '\\' + findData.cFileName)
					)
				);
			}
			else {
				items.push_back(
					std::make_shared<File>(
						File(*this, findData.cFileName)
					)
				);
			}
		} while (FindNextFile(handle, &findData));
		FindClose(handle);
	}

	return items;
}

std::string Directory::getName()
{
	return File::parsePath(getPath()).second;
}
