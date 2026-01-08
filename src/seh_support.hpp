#pragma once

#if defined(_WIN32)

struct seh_details
{
    unsigned long code = 0;
    const void* address = nullptr;
};

inline int capture_seh_info(unsigned long code, EXCEPTION_POINTERS* info, seh_details* out)
{
    if (out != nullptr)
    {
        out->code = code;
        if (info != nullptr && info->ExceptionRecord != nullptr)
            out->address = info->ExceptionRecord->ExceptionAddress;
        else
            out->address = nullptr;
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

#endif
