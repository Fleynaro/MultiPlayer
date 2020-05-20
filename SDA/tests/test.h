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
	4) создание читов, мп и т.д. на основе SDA: нужен скриптинг, средства визуализации, дебаггер и т.д
	5) вызов функций сделать

	NOW:
	1) если типа нет в гидре, но есть в сда, то заменить этот тип более простым. Для этого надо продублировать STypeUnit, где в копии указывать базовый тип(Ped*->void*, longlong->int64_t)
	2) сделать менеджер в thrift, через который можно управлять гидрой. например смена базового адреса, получения инфы и т.д

	//GHIDRA
	3) директории типов, итерация по ним, поиск типов
	4) транзакции
	5) typedef изменения, desctription exception, удаление и создание по новой - замена типов
	6) удаление по спискам
	7) сделать типом FunctionDeclaration


	СУТЬ: управлените низкоуровнеными вещами(структуры, vtable) на высоком уровне(классы, вирт. методы и т.д)
*/