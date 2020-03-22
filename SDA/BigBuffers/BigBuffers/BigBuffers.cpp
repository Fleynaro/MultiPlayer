#include <iostream>
#include <fstream>
#include <Windows.h>
#include "minhook/minhook-master/include/MinHook.h"
#include "buffer.h"

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


int main()
{
    //LPVOID pBuffer = AllocateBuffer(&getTestId);





   
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