#include "TestCodeToDecompile.h"
#include "pch.h"
#include <Windows.h>
#include <iostream>

int gVarrrr = 100;

int Func1(int a) {
	return a * 2;
}

class A {
public:
	int a = 10;
	int b = 20;
	long long c = 1000;
	uint64_t arr[3];

	A() = default;
};

class B {
public:
	int b = 0;
	A* a = new A;

	B() = default;
};

class C {
public:
	int c = 0;
	B* b = new B;

	C() = default;
};

A fff(A& a) {
	a.a = rand();
	a.b = rand();
	return a;
}

A g_a;
B g_b;
C g_c;

int TestFunctionToDecompile1() {
	int b = GetTickCount();

	/*b += func11(10) + func11(5);
	b *= -1;
	gVarrrr %= 21;*/
	/*if (b > 1) {
		b = func11(10) % 25;
		if (b == 2) {
			b ++;
		}
	}
	else {
		b = 5;

		if (b == 3 || b == 6) {
			b++;
			if (b == 3) {
				b++;
			}
			else {
				b--;
			}
		}
	}*/

	/*switch (b)
	{
	case 1:
		b *= 10;
		break;
	case 2:
		b *= 15 + b;
		break;
	case 5:
		b *= 30;
		break;
	}*/

	if (b >= 1) {
		b++;
	}
	if (b > 2) {
		b++;
	}
	if (b <= 3) {
		b++;
	}
	if (b < 4) {
		b++;
	}
	if (b == 5) {
		b++;
	}
	if (b != 6) {
		b++;
	}
	/*if (b == 10 && b == 20 || b == 30 && b == 40 && b == 50 || b == 60) {
		b++;
	}*/

	//SWITCH!!!

	/*while (b == 10 || (b == 20 && b == 30)) {
		b++;
		if (b == 100) {
			while (b < 500) {
				b += 2;
			}
		}


		b += Func1(10) + Func1(5);
	}*/

	/*auto a = g_c;
	auto obj = fff(*a.b->a);

	auto rr = &(&a)->b;

	auto op1 = int16_t(55);
	auto var = (int)op1 + (uint16_t*)2 + (op1 == -1) ? 1 : 2;*/

	/*int arr[2][3][4];
	for (int i = 0; i < 120; i++)
		arr[GetTickCount()][GetTickCount()][GetTickCount()] = 300;*/

	/*int a = GetTickCount() * GetTickCount() * GetTickCount() * GetTickCount();*/
	return b/*b * a + 100 + *//*arr[1][2][3] + */ /*obj.a + a.b->a->b*/;
}
