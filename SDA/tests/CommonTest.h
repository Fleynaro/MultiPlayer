#pragma once
#include "AbstractTest.h"
#include <Trigger/FunctionTriggerTableLog.h>
#include <Statistic/Function/Analysis/FunctionStatAnalyser.h>

class ProgramModuleFixtureStart : public ProgramModuleFixture {
public:
	ProgramModuleFixtureStart()
		: ProgramModuleFixture(true)
	{}
};

int main(int argc, char** argv);
void setPlayerPos();
void setPlayerVel();
void changeGvar();
int setRot(int a, float x, float y, float z, int c);

int calculateFunctionSize(byte* addr) {
	int size = 0;
	while (addr[size] != 0xCC)
		size++;
	return size;
}

typedef int* arrType;
int sumArray(arrType arr[3][2], char* str);

const char* g_testFuncName = "setRot";
extern int g_IntegerVal;



/*
	MYTODO:
	1) ���������� ����� ��� � �����. ���� ����� ������������ ������ ��������. ������� ��������� ������� ��� ������ ��������
	2) ������� ������������� �������� � ������ (����, �������, ���������� ����������, ����������� �������)
	3) ������� ���������� ������ ����� ��� ����������
	4) �������� �����, �� � �.�. �� ������ SDA: ����� ���������, �������� ������������, �������� � �.�
	5) ����� ������� �������

	NOW:
	1) ���� ���� ��� � �����, �� ���� � ���, �� �������� ���� ��� ����� �������. ��� ����� ���� �������������� STypeUnit, ��� � ����� ��������� ������� ���(Ped*->void*, longlong->int64_t)
	2) ������� �������� � thrift, ����� ������� ����� ��������� ������. �������� ����� �������� ������, ��������� ���� � �.�

	//GHIDRA
	3) ���������� �����, �������� �� ���, ����� �����
	4) ����������
	5) typedef ���������, desctription exception, �������� � �������� �� ����� - ������ �����
	6) �������� �� ������� *
	7) ������� ����� FunctionDeclaration *
	8) � id ������� ���. ����. �������� ���� � ���������� �����.
	9) ��������� ��� ���������� ���� �� �����, � �� ������� �� ��������� *
	10) ��������� ��


	����: ����������� ��������������� ������(���������, vtable) �� ������� ������(������, ����. ������ � �.�)
*/