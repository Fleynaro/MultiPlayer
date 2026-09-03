
#include <iostream>
#include <Windows.h>
#include <exception>
#include <excpt.h>
#include <vector>
#include <string>


// вспомогательная структура
typedef struct {
    SIZE_T RgnSize;
    DWORD dwRgnStorage; // MEM_*: Free, Image, Mapped, Private
    DWORD dwRgnBlocks;
    DWORD dwRgnGuardBlks; // если > 0, в регионе содержится стек потока
    BOOL fRgnIsAStack; // TRUE, если в регионе содержится стек потока
} VMQUERY_HELP;
// глобальная статическая переменная, содержащая значение — гранулярность выделения
// памяти на данном типе процессора; инициализируется при первом вызове VMQuery
static DWORD gs_dwAllocGran = 0;
///////////////////////////////////


// эта функция проходит по всем блокам в регионе
// и инициализирует структуру найденными значениями
static BOOL VMQueryHelp(HANDLE hProcess, LPCVOID pvAddress, VMQUERY_HELP* pVMQHelp)
{
    // каждый элемент содержит атрибут защиты страницы
    // (например, 0=зарезервирована, PAGE_NOACCESS, PAGE_READWRITE и т. д.)
    DWORD dwProtectBlock[4] = { 0 };
    ZeroMemory(pVMQHelp, sizeof(*pVMQHelp));
    // получаем базовый адрес региона, включающего переданный адрес памяти
    MEMORY_BASIC_INFORMATION mbi;
    BOOL fOk = (VirtualQueryEx(hProcess, pvAddress, &mbi, sizeof(mbi)) == sizeof(mbi));
    if (!fOk)
        return(fOk); // неверный адрес памяти, сообщаем об ошибке
        // проходим по региону, начиная с его базового адреса
        // (который никогда не изменится)
    PVOID pvRgnBaseAddress = mbi.AllocationBase;
    // начинаем с первого блока в регионе
    // (соответствующая переменная будет изменяться в цикле)
    PVOID pvAddressBlk = pvRgnBaseAddress;
    // запоминаем тип физической памяти, переданной данному блоку
    pVMQHelp->dwRgnStorage = mbi.Type;
    for (;;) {
        // получаем информацию о текущем блоке
        fOk = (VirtualQueryEx(hProcess, pvAddressBlk, &mbi, sizeof(mbi)) == sizeof(mbi));
        if (!fOk)
            break; // не удалось получить информацию; прекращаем цикл
            // проверяем, принадлежит ли текущий блок запрошенному региону
        if (mbi.AllocationBase != pvRgnBaseAddress)
            break; // блок принадлежит следующему региону; прекращаем цикл
            // блок принадлежит запрошенному региону
            // следующий оператор if служит для обнаружения стеков в Windows 98; в этой
            // системе стеки размещаются в последних 4 блоках региона: "зарезервированный",
            // PAGE_NOACCESS, PAGE_READWRITE и еще один "зарезервированный"
        if (pVMQHelp->dwRgnBlocks < 4) {
            // если это блок 0–3, запоминаем тип защиты блока в массиве
            dwProtectBlock[pVMQHelp->dwRgnBlocks] =
                (mbi.State == MEM_RESERVE) ? 0 : mbi.Protect;
        }
        else {
            // мы уже просмотрели 4 блока в этом регионе;
            // смещаем вниз элементы массива с атрибутами защиты
            MoveMemory(&dwProtectBlock[0], &dwProtectBlock[1],
                sizeof(dwProtectBlock) - sizeof(DWORD));
            // добавляем новые значения атрибутов защиты в конец массива
            dwProtectBlock[3] = (mbi.State == MEM_RESERVE) ? 0 : mbi.Protect;
        }
        pVMQHelp->dwRgnBlocks++; // увеличиваем счетчик блоков
        // в этом регионе на 1
        pVMQHelp->RgnSize += mbi.RegionSize; // добавляем размер блока к размеру региона
        // если блок имеет флаг PAGE_GUARD, добавляем 1 к счетчику блоков
        // с этим флагом
        if ((mbi.Protect & PAGE_GUARD) == PAGE_GUARD)
            pVMQHelp->dwRgnGuardBlks++;
        // Делаем наиболее вероятное предположение о типе физической памяти,
        // переданной данному блоку. Стопроцентной гарантии дать нельзя,
        // потому что некоторые блоки могли быть преобразованы из MEM_IMAGE
        // в MEM_PRIVATE или из MEM_MAPPED в MEM_PRIVATE; MEM_PRIVATE в любой
        // момент может быть замещен на MEM_IMAGE или MEM_MAPPED.
        if (pVMQHelp->dwRgnStorage == MEM_PRIVATE)
            pVMQHelp->dwRgnStorage = mbi.Type;
        // получаем адрес следующего блока
        pvAddressBlk = (PVOID)((PBYTE)pvAddressBlk + mbi.RegionSize);
    }

    // Обследовав регион, думаем: не стек ли это?
    // Windows 2000: да — если в регионе содержится хотя бы 1 блок с флагом PAGE_GUARD.
    // Windows 9x: да — если в регионе содержится хотя бы 4 блока,
    // и они имеют такие атрибуты:
    // 3-й блок от конца: зарезервирован
    // 2-й блок от конца: PAGE_NOACCESS
    // 1-й блок от конца: PAGE_READWRITE
    // последний блок: зарезервирован
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