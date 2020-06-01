
#include <iostream>
#include <string>
#include <Windows.h>

void showMessage(int counter)
{
    auto base = (std::uintptr_t)GetModuleHandle(NULL);
    printf("%i (addr = %p, off = %p)\n", counter, (void*)(std::uintptr_t)showMessage, (void*)((std::uintptr_t)showMessage - base));
}

int main()
{
    int counter = 0;
    while (true) {
        counter++;

        if (counter % 10 == 0) {
            showMessage(counter);
        }

        if (counter == 50) {
            throw std::exception("throw ex!");
        }

        Sleep(100);
    }

    std::cout << "end\n";
}