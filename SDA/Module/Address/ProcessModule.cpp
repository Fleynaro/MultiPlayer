#include "ProcessModule.h"
#include <Psapi.h>

using namespace CE;

int CE::GetModuleSize(HMODULE module) {
	MODULEINFO lpmodinfo;
	GetModuleInformation(GetCurrentProcess(), module, &lpmodinfo, sizeof(MODULEINFO));
	return lpmodinfo.SizeOfImage;
}

ProcessModule::ProcessModule(ProcessModuleManager* manager, HMODULE module, const std::string& name, const std::string& comment)
	: AddressRange(module, GetModuleSize(module)), Descrtiption(name, comment)
{
	if (getName().length() == 0) {
		setName(getFile().getFullname());
	}
}

std::uintptr_t ProcessModule::getBaseAddr() {
	return (std::uintptr_t)getMinAddress();
}

void* ProcessModule::toAbsAddr(int offset) {
	return offset == 0 ? nullptr : reinterpret_cast<void*>(getBaseAddr() + (std::uintptr_t)offset);
}

int ProcessModule::toRelAddr(void* addr) {
	return addr == nullptr ? 0 : static_cast<int>((std::uintptr_t)addr - getBaseAddr());
}

FS::File ProcessModule::getFile() {
	TCHAR szModName[MAX_PATH];
	GetModuleFileNameEx(GetCurrentProcess(), getHModule(), szModName, sizeof(szModName) / sizeof(TCHAR));
	return FS::File(szModName);
}

HMODULE ProcessModule::getHModule() {
	return HMODULE(getMinAddress());
}

ProcessModuleManager* ProcessModule::getManager() {
	return m_manager;
}

std::list<std::pair<std::string, void*>> CE::GetProcessModuleExportedFunctions(HMODULE hModule) {
    std::list<std::pair<std::string, void*>> result;
    BYTE* moduleBase = (BYTE*)hModule;

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(moduleBase + dosHdr->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExports;
    uint32_t i, NumberOfFuncNames;
    uint32_t* AddressOfNames;


    pExports = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (pExports != NULL) {
        NumberOfFuncNames = pExports->NumberOfNames;
        AddressOfNames = (uint32_t*)(moduleBase + pExports->AddressOfNames);

        for (i = 0; i < NumberOfFuncNames; ++i) {
            char* funcName = (char*)(moduleBase + *AddressOfNames);
            if (funcName != NULL) {

                auto AddressOfNameOrdinals = (uint16_t*)(moduleBase + pExports->AddressOfNameOrdinals);
                auto AddressOfFunctions = (uint32_t*)(moduleBase + pExports->AddressOfFunctions);

                auto idx = AddressOfNameOrdinals[i];
                auto funcAddr = (void*)(moduleBase + AddressOfFunctions[idx]);

                result.push_back(std::make_pair(funcName, funcAddr));
            }
            AddressOfNames++;
        }
    }
    return result;
}

std::list<std::pair<std::string, void*>> ProcessModule::getExportedFunctions() {
    return GetProcessModuleExportedFunctions(getHModule());
}
