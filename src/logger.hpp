#pragma once
#include "console.hpp"

namespace logger
{
    constexpr const char* prefix = "[unxorer]";

    template <typename... Args> inline void print(fmt::format_string<Args...> fmtstr, Args&&... args)
    {
        auto line = fmt::format("{} {}\n", prefix, fmt::format(fmtstr, std::forward<Args>(args)...));
        msg("%s", line.c_str());
        console::print(line);
    }

    inline void title()
    {
        msg("        %s\n", R"( __ _____ __ _____  _______ ____)");
        msg("        %s\n", R"(/ // / _ \\ \ / _ \/ __/ -_) __/)");
        msg("        %s\n", R"(\_,_/_//_/_\_\\___/_/  \__/_/   )");

        msg("   %s\n", fmt::format("build on {0} from {1}", BUILD_DATE, GIT_HASH).c_str());
    }
}