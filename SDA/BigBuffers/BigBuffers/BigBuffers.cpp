#include <iostream>
#include <fstream>
#include <Windows.h>
#include "minhook/minhook-master/include/MinHook.h"
#include "buffer.h"

#include "gtest/gtest.h"


using namespace std;

/*
    При разрабокте оттакливаемся от производительности вставки записей. Для этого:
    1) Избегаем мьютексов
    2) Делаем много потоков - workers. 
    3) Делаем эффективного менеджера(одного, нет раздедения на арг и рет)
    4) Каждый worker работает со своим буфером
    5) Может случиться, что каждый worker будет потом занят записью содержимого буфера в файл. Тогда будут серьезные подвисания.
        Решение: создать вспомогательные потоки, которые будут спать и просыпаться по запросу менеджера. Если worker заполнен, то забираем у него буфер и передаем спящему потоку(можно одному, у него очередь буферов на запись в файл)

    !!!ВАРИАНТ 2: есть один активный буфер. В него производятся записи. Если буфер заполнился, то отправляем его в очердь на запись в файл в разные потоки. Просто создаем поток новый. Новый активный буфер выделяется в памяти.


    Также создадим свой ByteStream. Его задача - упаковывать компактно данные о вызовах. Соблюдать выравнивание, ибо лучше записывать словами в память, чем байтами!
    Заголовки:  [тип записи: before/after call] [id триггера] [id функции] [unixtime] [guid] [запись битами сюда общей инфы: есть ли строка, есть ли указ,массив - нужно для поиска]
                before: [кол-во аргументов N] [список типов(byte,int,char,object) для каждого аргумента + [pointer/not pointer] N - 4 бита] [сами аргументы N]
                аргумент число int - 4 байта
                аргумент char[32](это pointer, проверяем на массив) - [адрес массива] [число символов] [raw string]
                аргумент float[4] - то же, что и вверху. это массив. макс. число элементов 65535
                ...
                опционально записываем фрагмент стека нужного размера

    В итоге у нас будет папка, где будет куча файлов-буферов. Сделать анализатор этих файлов:
    1) Анализ типов значений
    2) Анализ строк
    3) Аанализ объектов: например где этот объект вызывался, где изменялся и т.д
    4) Встречалось ли какое-то значение в стеке(строка)

    Для каждого типа анализа свой класс, у каждого свои результаты. Некоторые можно сохранить в БД

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