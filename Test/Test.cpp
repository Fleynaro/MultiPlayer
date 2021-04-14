#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>

using namespace std;

/*
	������:
	1) https://habr.com/ru/post/266831/
	2) 
*/

// �������� ��������� � ������ ��� ������� (����������� ����� ����� CFF Explorer!)
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
	// the file offset is different than the in memory offset because of section alignment (�.�. ����� ��� ������� ��-�� ������������)
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
	//
	auto f = read_exe("R:\\Rockstar Games\\Grand Theft Auto V\\GTA5_dump.exe"); // ScriptHookV.dll, GTA5_dump.exe, GTA5.exe
	
	auto& dos_header = *(IMAGE_DOS_HEADER*)f;

	// ���������, ������ ������ MZ
	auto e_magic = (char*)&dos_header.e_magic;
	if (string(e_magic, 2) != "MZ")
		throw std::exception();

	auto& nt_headers = *(IMAGE_NT_HEADERS*)(f + dos_header.e_lfanew);
	
	// ��� ���� ���������, ������� ������ ����� PE\x0\x0
	auto signature = (char*)&nt_headers.Signature;
	if (string(signature, 2) != "PE")
		throw std::exception();

	auto& file_header = nt_headers.FileHeader;

	auto& optional_header = nt_headers.OptionalHeader;

	// ����� �� �������� DataDirectory(�.�. �� nt_headers) ���� �� ������ ���� ������
	auto section_headers = (IMAGE_SECTION_HEADER*)(f + dos_header.e_lfanew + sizeof(nt_headers));

	// ������ ����
	auto& code_section = section_headers[0];
	auto& data_section = section_headers[4];

	// ����� ����� � ��������� (������� main)
	printf("AddressOfEntryPoint = %p (first cmd = %x)\n\n", optional_header.AddressOfEntryPoint, *(uint64_t*)(f + Rva2Offset(optional_header.AddressOfEntryPoint, section_headers, &nt_headers)));

	// ������
	auto& import_dir = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto import_descs = (IMAGE_IMPORT_DESCRIPTOR*)(f + Rva2Offset(import_dir.VirtualAddress, section_headers, &nt_headers));
	
	int i = 0;
	while (import_descs[i].Name != NULL) { // ������ �� ���� ����������� DLL
		auto& dll = import_descs[i];
		auto dll_name = string(f + Rva2Offset(dll.Name, section_headers, &nt_headers));
		printf("DLL: %s\n", dll_name.c_str());

		auto orig_thunk_arr = (IMAGE_THUNK_DATA64*)(f + Rva2Offset(dll.OriginalFirstThunk, section_headers, &nt_headers));
		auto thunk_arr = (IMAGE_THUNK_DATA64*)(f + Rva2Offset(dll.FirstThunk, section_headers, &nt_headers));

		int j = 0;
		while (orig_thunk_arr[j].u1.AddressOfData && !(orig_thunk_arr[j].u1.AddressOfData >> 31)) { // ������ �� ���� �������� ������ DLL (���� ��������� ��� 1, �� ��� ����� �������������� �������)
			auto& dll_func = *(IMAGE_IMPORT_BY_NAME*)(f + Rva2Offset(orig_thunk_arr[j].u1.AddressOfData, section_headers, &nt_headers));
			auto dll_func_name = string(&dll_func.Name[0]);
			printf("-----> %s (hint=%i, addr=0x%p)\n", dll_func_name.c_str(), dll_func.Hint, thunk_arr[j].u1.Function);

			j++;
		}

		printf("\n\n");
		i++;
	}

	system("pause");
}
