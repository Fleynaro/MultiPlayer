#include "TestCodeToDecompile.h"
#include "pch.h"

int gVarrrr = 100;

int Func1(int a) {
	return a * 2;
}

void TestFunctionToDecompile1() {
	int b = 2;

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

	/*if (b == 10 && b == 20 && b == 30 && b == 40) {
		b++;
	}*/
	/*if (b == 10 && b == 20 || b == 30 && b == 40 && b == 50 || b == 60) {
		b++;
	}*/

	//SWITCH!!!

	while (b == 10 || (b == 20 && b == 30)) {
		b++;
		if (b == 100) {
			while (b < 500) {
				b += 2;
			}
		}


		b += Func1(10) + Func1(5);
	}

	b = 100;
}
