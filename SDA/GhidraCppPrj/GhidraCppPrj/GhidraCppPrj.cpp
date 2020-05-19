#include <iostream>
#include <string>

using namespace std;

void func(const char* name) {
    auto idx = min(2, max(1, min(1, rand())));
    if (name[idx] == '1' || name[idx] == '3' || name[idx] == '5') {
        printf(name);
    }
}


class Screen {
public:
    float m_width;
    float m_height;

    Screen(float width = 1.0, float height = 2.0)
        : m_width(width), m_height(height)
    {
        func("FUN: Screen::constructor");
    }

    float getSquare() {
        func("FUN: Screen::getSquare");
        return m_width * m_height;
    }

    virtual float getVolume() {
        func("FUN: Screen::getVolume");
        return getSquare();
    }

    virtual void zero() {
        func("FUN: Screen::zero");
        m_width = 0.0;
        m_height = 0.0;
    }
};

class Screen3D : public Screen {
public:
    float m_depth;
    Screen3D(float width, float height, float depth)
        : Screen(width, height), m_depth(depth)
    {
        func("FUN: Screen3D::constructor");
    }

    float getVolume() override {
        func("FUN: Screen3D::getVolume");
        return getSquare() * m_depth;
    }

    void zero() override {
        func("FUN: Screen3D::zero");
        Screen::zero();
        m_depth = 0.0;
    }
};

Screen g_screen;

int someFunction()
{
    func("FUN: someFunction");

    int a = 5;
    a += rand();
    a += pow(a, 2);
    a += sin(a);
    a += cos(a);

    Screen* screen = new Screen(1280.f, 720.f);
    a += screen->getSquare();
    Screen3D* screen3d = new Screen3D(1280.f, 720.f, 2.f);
    a += screen3d->getVolume();
    a += g_screen.getSquare();
    g_screen.zero();
    a += g_screen.getSquare();
    screen->zero();
    return a;
}

int main()
{
    func("FUN: main");
    

    printf("res1 = %i", someFunction());
    printf("res2 = %i", someFunction());
    printf("res3 = %i", someFunction());

    system("pause");
}