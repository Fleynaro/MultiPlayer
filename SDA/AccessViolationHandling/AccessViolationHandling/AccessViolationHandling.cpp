
#include <iostream>
#include <Windows.h>
#include <exception>
#include <excpt.h>
#include <vector>
#include <string>


// ��������������� ���������
typedef struct {
    SIZE_T RgnSize;
    DWORD dwRgnStorage; // MEM_*: Free, Image, Mapped, Private
    DWORD dwRgnBlocks;
    DWORD dwRgnGuardBlks; // ���� > 0, � ������� ���������� ���� ������
    BOOL fRgnIsAStack; // TRUE, ���� � ������� ���������� ���� ������
} VMQUERY_HELP;
// ���������� ����������� ����������, ���������� �������� � ������������� ���������
// ������ �� ������ ���� ����������; ���������������� ��� ������ ������ VMQuery
static DWORD gs_dwAllocGran = 0;
///////////////////////////////////


// ��� ������� �������� �� ���� ������ � �������
// � �������������� ��������� ���������� ����������
static BOOL VMQueryHelp(HANDLE hProcess, LPCVOID pvAddress, VMQUERY_HELP* pVMQHelp)
{
    // ������ ������� �������� ������� ������ ��������
    // (��������, 0=���������������, PAGE_NOACCESS, PAGE_READWRITE � �. �.)
    DWORD dwProtectBlock[4] = { 0 };
    ZeroMemory(pVMQHelp, sizeof(*pVMQHelp));
    // �������� ������� ����� �������, ����������� ���������� ����� ������
    MEMORY_BASIC_INFORMATION mbi;
    BOOL fOk = (VirtualQueryEx(hProcess, pvAddress, &mbi, sizeof(mbi)) == sizeof(mbi));
    if (!fOk)
        return(fOk); // �������� ����� ������, �������� �� ������
        // �������� �� �������, ������� � ��� �������� ������
        // (������� ������� �� ���������)
    PVOID pvRgnBaseAddress = mbi.AllocationBase;
    // �������� � ������� ����� � �������
    // (��������������� ���������� ����� ���������� � �����)
    PVOID pvAddressBlk = pvRgnBaseAddress;
    // ���������� ��� ���������� ������, ���������� ������� �����
    pVMQHelp->dwRgnStorage = mbi.Type;
    for (;;) {
        // �������� ���������� � ������� �����
        fOk = (VirtualQueryEx(hProcess, pvAddressBlk, &mbi, sizeof(mbi)) == sizeof(mbi));
        if (!fOk)
            break; // �� ������� �������� ����������; ���������� ����
            // ���������, ����������� �� ������� ���� ������������ �������
        if (mbi.AllocationBase != pvRgnBaseAddress)
            break; // ���� ����������� ���������� �������; ���������� ����
            // ���� ����������� ������������ �������
            // ��������� �������� if ������ ��� ����������� ������ � Windows 98; � ����
            // ������� ����� ����������� � ��������� 4 ������ �������: "�����������������",
            // PAGE_NOACCESS, PAGE_READWRITE � ��� ���� "�����������������"
        if (pVMQHelp->dwRgnBlocks < 4) {
            // ���� ��� ���� 0�3, ���������� ��� ������ ����� � �������
            dwProtectBlock[pVMQHelp->dwRgnBlocks] =
                (mbi.State == MEM_RESERVE) ? 0 : mbi.Protect;
        }
        else {
            // �� ��� ����������� 4 ����� � ���� �������;
            // ������� ���� �������� ������� � ���������� ������
            MoveMemory(&dwProtectBlock[0], &dwProtectBlock[1],
                sizeof(dwProtectBlock) - sizeof(DWORD));
            // ��������� ����� �������� ��������� ������ � ����� �������
            dwProtectBlock[3] = (mbi.State == MEM_RESERVE) ? 0 : mbi.Protect;
        }
        pVMQHelp->dwRgnBlocks++; // ����������� ������� ������
        // � ���� ������� �� 1
        pVMQHelp->RgnSize += mbi.RegionSize; // ��������� ������ ����� � ������� �������
        // ���� ���� ����� ���� PAGE_GUARD, ��������� 1 � �������� ������
        // � ���� ������
        if ((mbi.Protect & PAGE_GUARD) == PAGE_GUARD)
            pVMQHelp->dwRgnGuardBlks++;
        // ������ �������� ��������� ������������� � ���� ���������� ������,
        // ���������� ������� �����. ������������� �������� ���� ������,
        // ������ ��� ��������� ����� ����� ���� ������������� �� MEM_IMAGE
        // � MEM_PRIVATE ��� �� MEM_MAPPED � MEM_PRIVATE; MEM_PRIVATE � �����
        // ������ ����� ���� ������� �� MEM_IMAGE ��� MEM_MAPPED.
        if (pVMQHelp->dwRgnStorage == MEM_PRIVATE)
            pVMQHelp->dwRgnStorage = mbi.Type;
        // �������� ����� ���������� �����
        pvAddressBlk = (PVOID)((PBYTE)pvAddressBlk + mbi.RegionSize);
    }

    // ���������� ������, ������: �� ���� �� ���?
    // Windows 2000: �� � ���� � ������� ���������� ���� �� 1 ���� � ������ PAGE_GUARD.
    // Windows 9x: �� � ���� � ������� ���������� ���� �� 4 �����,
    // � ��� ����� ����� ��������:
    // 3-� ���� �� �����: ��������������
    // 2-� ���� �� �����: PAGE_NOACCESS
    // 1-� ���� �� �����: PAGE_READWRITE
    // ��������� ����: ��������������
    pVMQHelp->fRgnIsAStack =
        (pVMQHelp->dwRgnGuardBlks > 0) ||
        ((pVMQHelp->dwRgnBlocks >= 4) &&
        (dwProtectBlock[0] == 0) &&
            (dwProtectBlock[1] == PAGE_NOACCESS) &&
            (dwProtectBlock[2] == PAGE_READWRITE) &&
            (dwProtectBlock[3] == 0));
    return(TRUE);
}



int filter(unsigned int code)
{
    if (code == EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_EXECUTE_HANDLER;

    return EXCEPTION_CONTINUE_SEARCH;
}

int g_var = 102;
const int g_var2 = 102;
int g_var3;

#include <map>
int main()
{
    std::map<int, std::string> m{ {1, "potato"}, {20, "banan33a"}, {45, "ban44ana"}, {200, "bana66na"} };

    for (auto it = --m.end(); it->first >= 20;  it--) {
        auto nodeHandler = m.extract(it->first);
        nodeHandler.key() += 10;
        m.insert(std::move(nodeHandler));
    }


    return 0;
    std::cout << "Hello World!\n";
    /*__try {
        *(int*)0 = 0;
    }
    __except (filter(GetExceptionCode()))
    {
        printf("Exception Caught: %x\n");
    }*/


    //PEXCEPTION_POINTERS ExceptionPointer = nullptr;
    //__try {
    //   // *(int*)0 = 0;
    //}
    //__except (ExceptionPointer = GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)
    //{
    //    printf("\n\nexception %x\n", (uint64_t)ExceptionPointer->ExceptionRecord->ExceptionAddress);

    //    switch (ExceptionPointer->ExceptionRecord->ExceptionCode)
    //    {
    //    case EXCEPTION_ACCESS_VIOLATION:
    //        printf("EXCEPTION_ACCESS_VIOLATION");
    //        break;
    //    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    //        printf("EXCEPTION_INT_DIVIDE_BY_ZERO");
    //        break;
    //    default:
    //        break;
    //    }
    //}

    void* addr = (void*)&g_var3;
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(addr, &mbi, sizeof(mbi));


    HMODULE module = (HMODULE)mbi.AllocationBase;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);
    PIMAGE_FILE_HEADER pifh = (PIMAGE_FILE_HEADER)&pinh->FileHeader;
    
    struct SectionHeader {
        void* m_baseAddr;
        std::string m_name;
        int m_size;

        bool isIn(void* addr) {
            return (std::uintptr_t)addr >= (std::uintptr_t)m_baseAddr && (std::uintptr_t)addr <= (std::uintptr_t)m_baseAddr + m_size;
        }
    };

    std::vector<SectionHeader> m_headers;
    int selIdx = -1;
    for (int idx = 0; idx < pifh->NumberOfSections; idx++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((BYTE*)pinh + sizeof(IMAGE_NT_HEADERS) + idx * sizeof(IMAGE_SECTION_HEADER));
        
        SectionHeader sh;
        sh.m_name = (char*)pish->Name;
        sh.m_baseAddr = (void*)((std::uintptr_t)module + pish->VirtualAddress);
        sh.m_size = pish->Misc.VirtualSize;

        if (sh.isIn(addr)) {
            selIdx = idx;
        }

        m_headers.push_back(sh);
    }
    
    /*IMAGE_DOS_HEADER* idm = (IMAGE_DOS_HEADER*)module;

    auto headers = (IMAGE_NT_HEADERS*)(module + idm->e_lfanew);
    auto& file_header = headers->FileHeader;
    auto count = file_header.NumberOfSections;*/
   
    char buffer[MAX_PATH];
    GetModuleFileNameA(module, buffer, MAX_PATH);

    /*try {
        *(int*)0 = 0;
    }
    catch (std::exception ex) {
        printf("Exception Caught: %s\n", ex.what());
    }*/


    printf("\n");
    system("pause");
    return 0;
}