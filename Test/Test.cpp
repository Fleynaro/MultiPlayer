#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>

using namespace std;

/*
	—татьи:
	1) https://habr.com/ru/post/266831/
	2) 
*/

// загрузка бинарника в пам€ть дл€ анализа (параллельно юзать прогу CFF Explorer!)
char* read_exe(const char* path) {
	//open file
	std::ifstream infile(path, std::ios::binary);

	//get length of file
	infile.seekg(0, std::ios::end);
	size_t length = infile.tellg();
	infile.seekg(0, std::ios::beg);

	char* buffer = new char[length];

	//read file
	infile.read(buffer, length);

	return buffer;
}

DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	// the file offset is different than the in memory offset because of section alignment.
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

int main()
{
	auto f = read_exe("R:\\Rockstar Games\\Grand Theft Auto V\\GTA5.exe");
	
	auto& dos_header = *(IMAGE_DOS_HEADER*)f;

	// сигнатура, всегда равна€ MZ
	auto e_magic = (char*)&dos_header.e_magic;
	if (string(e_magic, 2) != "MZ")
		throw std::exception();

	auto& nt_headers = *(IMAGE_NT_HEADERS*)(f + dos_header.e_lfanew);
	
	// еще одна сигнатура, котора€ всегда равна PE\x0\x0
	auto signature = (char*)&nt_headers.Signature;
	if (string(signature, 2) != "PE")
		throw std::exception();

	auto& file_header = nt_headers.FileHeader;

	auto& optional_header = nt_headers.OptionalHeader;

	// сразу за массивом DataDirectory(т.е. за nt_headers) друг за другом идут секции
	auto section_headers = (IMAGE_SECTION_HEADER*)(f + dos_header.e_lfanew + sizeof(nt_headers));

	// секции кода
	auto& code_section = section_headers[0];
	auto& data_section = section_headers[4];

	auto& import_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto import_descs = (IMAGE_IMPORT_DESCRIPTOR*)(f + Rva2Offset(import_dir.VirtualAddress, section_headers, &nt_headers));
	
	auto& dll1 = import_descs[0];
	auto val = dll1.OriginalFirstThunk;

	system("pause");
}
