#include <iostream>
#include <fstream>
#include <Windows.h>
#include "minhook/minhook-master/include/MinHook.h"
#include "buffer.h"

#include "gtest/gtest.h"


using namespace std;

/*
    ��� ���������� ������������� �� ������������������ ������� �������. ��� �����:
    1) �������� ���������
    2) ������ ����� ������� - workers. 
    3) ������ ������������ ���������(������, ��� ���������� �� ��� � ���)
    4) ������ worker �������� �� ����� �������
    5) ����� ���������, ��� ������ worker ����� ����� ����� ������� ����������� ������ � ����. ����� ����� ��������� ����������.
        �������: ������� ��������������� ������, ������� ����� ����� � ����������� �� ������� ���������. ���� worker ��������, �� �������� � ���� ����� � �������� ������� ������(����� ������, � ���� ������� ������� �� ������ � ����)

    !!!������� 2: ���� ���� �������� �����. � ���� ������������ ������. ���� ����� ����������, �� ���������� ��� � ������ �� ������ � ���� � ������ ������. ������ ������� ����� �����. ����� �������� ����� ���������� � ������.


    ����� �������� ���� ByteStream. ��� ������ - ����������� ��������� ������ � �������. ��������� ������������, ��� ����� ���������� ������� � ������, ��� �������!
    ���������:  [��� ������: before/after call] [id ��������] [id �������] [unixtime] [guid] [������ ������ ���� ����� ����: ���� �� ������, ���� �� ����,������ - ����� ��� ������]
                before: [���-�� ���������� N] [������ �����(byte,int,char,object) ��� ������� ��������� + [pointer/not pointer] N - 4 ����] [���� ��������� N]
                �������� ����� int - 4 �����
                �������� char[32](��� pointer, ��������� �� ������) - [����� �������] [����� ��������] [raw string]
                �������� float[4] - �� ��, ��� � ������. ��� ������. ����. ����� ��������� 65535
                ...
                ����������� ���������� �������� ����� ������� �������

    � ����� � ��� ����� �����, ��� ����� ���� ������-�������. ������� ���������� ���� ������:
    1) ������ ����� ��������
    2) ������ �����
    3) ������� ��������: �������� ��� ���� ������ ���������, ��� ��������� � �.�
    4) ����������� �� �����-�� �������� � �����(������)

    ��� ������� ���� ������� ���� �����, � ������� ���� ����������. ��������� ����� ��������� � ��

*/

int g_var = 100023;

int getTestId(int a) {
    return g_var;
}



typedef int (*getTestId_)(int);


getTestId_ origFunc = nullptr;
int getTestHooked(int a) {
    return origFunc(a + 1) + 2;
}

void shellcode_export_finder(BYTE* moduleBase);
int main(int argc, char** argv)
{
    //LPVOID pBuffer = AllocateBuffer(&getTestId);
    

    int a = 5;

    char* func = (char*)&getTestId;
    DWORD old;
    VirtualProtect(func, 1000, PAGE_EXECUTE_READWRITE, &old); //hook
    func[4] = 0xCC;
    func[5] = 0x90;


    PEXCEPTION_POINTERS ExceptionPointer = nullptr;
    __try {
        getTestId(5);
    }
    __except (ExceptionPointer = GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)
    {
        printf("\n\nexception %x\n", (uint64_t)ExceptionPointer->ExceptionRecord->ExceptionAddress);

        switch (ExceptionPointer->ExceptionRecord->ExceptionCode)
        {
        case EXCEPTION_ACCESS_VIOLATION:
            printf("EXCEPTION_ACCESS_VIOLATION");
            break;
        case EXCEPTION_BREAKPOINT:
            printf("EXCEPTION_BREAKPOINT");
            break;
        default:
            break;
        }
    }

    //shellcode_export_finder((BYTE*)GetModuleHandle(NULL));
   
    // Initialize MinHook.
    if (MH_Initialize() != MH_OK)
    {
        return 1;
    }

    // Create a hook for MessageBoxW, in disabled state.
    if (MH_CreateHook(&getTestId, &getTestHooked,
        reinterpret_cast<LPVOID*>(&origFunc)) != MH_OK)
    {
        return 1;
    }



    int result = getTestId(rand());
    printf("result = %i", result);


    // Enable the hook for MessageBoxW.
    if (MH_EnableHook(&getTestId) != MH_OK)
    {
        return 1;
    }


    result = getTestId(2);

    

    // Disable the hook for MessageBoxW.
    if (MH_DisableHook(&getTestHooked) != MH_OK)
    {
        return 1;
    }

    

    // Uninitialize MinHook.
    if (MH_Uninitialize() != MH_OK)
    {
        return 1;
    }

    return 0;
}

//extern "C"
//{
//    __declspec(dllimport) int sum(int a, int b);
//}


#include <winnt.h>


void shellcode_export_finder(BYTE* moduleBase)
{
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(moduleBase + dosHdr->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExports;
    uint32_t i, NumberOfFuncNames;
    uint32_t* AddressOfNames;

    std::list<int> arr;
    arr.push_back(5);
    
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

                if (std::string(funcName) == "UnlockFile") {
                    auto addr = &UnlockFile;
                    int b = 5;
                }
                printf("Export: %s %i\n", funcName, arr.size());
            }
            else {
                int bb = 5;
            }
            AddressOfNames++;

        }
    }

    return;
}

#include <psapi.h>
int PrintModules()
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    hProcess = GetCurrentProcess();
    if (NULL == hProcess)
        return 1;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                printf("\t%s (0x%08X)\n", szModName, hMods[i]);
            }
        }
    }

    return 0;
}

class A {
public:
    int x = 5;
    virtual int get() { return x; }
};

class B {
public:
    int y = 3;
    virtual int get2() { return 0; }
};

class C : public A, public B {
public:
    int y = 3;
    int get() override { return y; }
};

class D : public A {
public:
    int f = 3;
};

int main2(int argc, char** argv)
{
    // Initialize MinHook.
    if (MH_Initialize() != MH_OK)
    {
        return 1;
    }

    A* a = new C;
    if (auto rrr = dynamic_cast<B*>(a)) {
        int b = 5;
    }

    A* d = new D;
    if (auto rrr = dynamic_cast<B*>(d)) {
        int b = 7;
    }
    return 0;
}