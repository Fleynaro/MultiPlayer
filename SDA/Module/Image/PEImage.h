#pragma once
#include "IImage.h"

namespace CE
{
	class PEImage : public IImage
	{
		byte* m_data;
		int m_size;
		PIMAGE_NT_HEADERS m_pImgNtHeaders;
		PIMAGE_SECTION_HEADER m_pImgSecHeader;
	public:
		PEImage(byte* data, int size)
			: m_data(data), m_size(size)
		{
			parse();
		}

		byte* getData() override {
			return m_data;
		}

		int getSize() override {
			return m_size;
		}

		int getOffsetOfEntryPoint() override {
			return (int)rvaToOffset(m_pImgNtHeaders->OptionalHeader.AddressOfEntryPoint);
		}

		static void LoadPEImage(const std::string& filename, char** buffer, int* size) {
			//open file
			std::ifstream infile(filename, std::ios::binary);

			//get length of file
			infile.seekg(0, std::ios::end);
			*size = infile.tellg();
			infile.seekg(0, std::ios::beg);

			*buffer = new char[*size];

			//read file
			infile.read(*buffer, *size);
		}

	private:
		void parse() {
			auto& dos_header = *(IMAGE_DOS_HEADER*)m_data;
			auto e_magic = (char*)&dos_header.e_magic;
			if (std::string(e_magic, 2) != "MZ")
				throw std::exception();

			m_pImgNtHeaders = (PIMAGE_NT_HEADERS)(m_data + dos_header.e_lfanew);

			auto signature = (char*)&m_pImgNtHeaders->Signature;
			if (std::string(signature, 2) != "PE")
				throw std::exception();

			m_pImgSecHeader = (PIMAGE_SECTION_HEADER)(m_data + dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS));
		}

		DWORD rvaToOffset(DWORD rva)
		{
			size_t i = 0;
			PIMAGE_SECTION_HEADER pSeh;
			if (rva == 0) {
				return (rva);
			}
			pSeh = m_pImgSecHeader;
			for (i = 0; i < m_pImgNtHeaders->FileHeader.NumberOfSections; i++) {
				if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
					pSeh->Misc.VirtualSize) {
					break;
				}
				pSeh++;
			}
			return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
		}
	};
};