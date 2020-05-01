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

int main2(int argc, char** argv)
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

    system("pause");

    return 1;


   
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



//Unit tests
int sum(int a, int b) {
    return a + b;
}

TEST(BasicFunc, Sum) {
    ASSERT_EQ(5, sum(2, 3));
}

class myTestFixture1 : public ::testing::Test {
public:
    myTestFixture1() {
        
    }

    void SetUp() {
        int a = 5;
        m_list.push_back(5);
    }

    void TearDown() {
        int b = 5;
    }

    ~myTestFixture1() {
       
    }

    std::list<int> m_list;
};

TEST_F(myTestFixture1, UnitTest1) {
    ASSERT_GT(m_list.size(), 0);
}

TEST_F(myTestFixture1, UnitTest2) {
    ASSERT_GT(m_list.size(), 0);
}


int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}