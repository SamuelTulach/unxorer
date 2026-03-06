#include "global.hpp"

#if defined(_WIN32)
extern "C" FILE* __cdecl __acrt_iob_func(unsigned index);
#endif

void console::init()
{
#ifdef _WIN32
    AllocConsole();

    FILE* in_file = nullptr;
    FILE* out_file = nullptr;
    FILE* in_stream = __acrt_iob_func(0);
    FILE* out_stream = __acrt_iob_func(1);

    freopen_s(&in_file, "CONIN$", "r", in_stream);
    freopen_s(&out_file, "CONOUT$", "w", out_stream);
#endif
}

void console::print(const std::string& message)
{
    std::cout << message;
}
