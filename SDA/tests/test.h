#pragma once
//SDA
#include <Program.h>
#include <Trigger/FunctionTriggerTableLog.h>
#include <Statistic/Function/Analysis/FunctionStatAnalyser.h>

//gtest
#define _DEBUG
#undef NDEBUG
#include "gtest/gtest.h"

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



/*
	MYTODO:
	1) ���������� ����� ��� � �����. ���� ����� ������������ ������ ��������. ������� ��������� ������� ��� ������ ��������
	2) ������� ������������� �������� � ������ (����, �������, ���������� ����������, ����������� �������)
	3) ������� ���������� ������ ����� ��� ����������

	NOW:
	1) ���� ������� ���������� � �� � �������� � �����*
	2) ������ ������ ��� �����-��������, ������� ���� ��������� � �� �� ���������� �������
	3) ������� ������ ��� �� ��� � ��(i,u,d). ��������: ���� ��������� ������ ��� ������ �� ���� *
	4) ������� �������� � ������� ����������� ��������. �������� �� ����� - ��������������� �������.
		4.1) �������� - commit, �������� - upload
	5) ������ DomainObject - GhidraObject *
	6) ������ ������� ���������� ���������� ������������ ������� ������ ������������� � �������� add,commit,push,pull,pullAllExcept,, �.�. ��� � git
	7) �� commit � sync*
	8) ��������� ���� �����-�������� �� ���������� �������, ���� ��������� ��������
	9) ���� �������� �������*
	10) ��� �������� ������� ��������� �������
*/