#pragma once
#include "console.hpp"

namespace logger
{
    constexpr const char* prefix = "[unxorer]";

    template <typename... Args> inline std::string format_line(fmt::format_string<Args...> fmtstr, Args&&... args)
    {
        return fmt::format("{} {}\n", prefix, fmt::format(fmtstr, std::forward<Args>(args)...));
    }

    inline void emit(const std::string& line)
    {
        msg("%s", line.c_str());
    }

    template <typename... Args> inline void info(fmt::format_string<Args...> fmtstr, Args&&... args)
    {
        emit(format_line(fmtstr, std::forward<Args>(args)...));
    }

    template <typename... Args> inline void debug(fmt::format_string<Args...> fmtstr, Args&&... args)
    {
#ifndef NDEBUG
        const std::string line = format_line(fmtstr, std::forward<Args>(args)...);
        emit(line);
        console::print(line);
#endif
    }

    inline void title()
    {
        msg("        %s\n", R"( __ _____ __ _____  _______ ____)");
        msg("        %s\n", R"(/ // / _ \\ \ / _ \/ __/ -_) __/)");
        msg("        %s\n", R"(\_,_/_//_/_\_\\___/_/  \__/_/   )");

        msg("   %s\n", fmt::format("build on {0} from {1}", BUILD_DATE, GIT_HASH).c_str());
    }
}
