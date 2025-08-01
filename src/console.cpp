#include <Windows.h>
#include <iostream>
#include "console.hpp"

void console::init()
{
    AllocConsole();
    freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
}

void console::print(const std::string& message)
{
    std::cout << message;
}
