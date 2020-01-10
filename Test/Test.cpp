
#include <iostream>
#include "main.h"


#include "Utility/MemoryHandle.h"
#include "Utility/Pattern.h"




int add(int x, int y)
{
	return x + y;
}


int main()
{
    std::cout << "Test\n\n\n";

	int a = 50000000;

	auto module = Memory::Module::main();

	Memory::Handle h(&a);
	int b = 0;
	h = h.add(0);
	int c = 3;
	//h.set(&c);

	int* p1 = new int;
	*p1 = 2;
	int** p2 = &p1;



	bool menuOpen = false;
	Memory::Object<bool> isMenuOpen(&menuOpen);
	Memory::Function<int(int, int)> closeMenu;
	isMenuOpen.set(true);
	std::cout << "b = " << isMenuOpen.getHandle().get<int>() << "\n\n";




	Pattern pattern("51 ? 23 ?? f2 13 ? 7f");



	std::cout << "\n\n\n";
	system("pause");
}
