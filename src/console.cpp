#ifdef _WIN32
#include <Windows.h>
#endif
#include <iostream>
#include "console.hpp"

void console::init()
{
#ifdef _WIN32
    AllocConsole();
    freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
#endif
}

void console::print(const std::string& message)
{
    std::cout << message;
}
