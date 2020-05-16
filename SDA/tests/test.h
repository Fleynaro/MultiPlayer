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
	1) Библиотека типов как в гидре. Типы могут принадлежать модулю процесса. Сделать корневыми папками эти модули процесса
	2) Сделать синхронизацию объектов с гидрой (типы, функции, глобальные переменные, виртуальные таблицы)
	3) Сделать управление гидрой через это приложение

	NOW:
	1) есть таблица транзакций в бд и коммитов в гидру*
	2) коммит только тех гидра-объектов, которые были сохранены в бд до последнего коммита
	3) сделать маппер так же как в бд(i,u,d). Проблема: явно указывать инсерт или апдейт не надо *
	4) сделать загрузку с выбором загружаемых объектов. Загрузка из гидры - высокоуровневая штукова.
		4.1) загрузка - commit, выгрузка - upload
	5) вместо DomainObject - GhidraObject *
	6) вместо объекта глобальной транзакции предлагается сделать объект синхронизации с методами add,commit,push,pull,pullAllExcept,, т.е. как в git
	7) не commit а sync*
	8) загрузчик всех гидра-объектов по некоторому условию, даже удаленных объектов
	9) флаг удаления объекта*
	10) при создании объекта указывать мапперы
*/