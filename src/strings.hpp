#pragma once

namespace strings
{
    inline bool is_ascii_printable(const uint8_t c) noexcept
    {
        return (c >= 0x20 && c <= 0x7E) || c == 0x09 || c == 0x0A || c == 0x0D;
    }

    inline bool is_utf16_printable(const uint16_t w) noexcept
    {
        return (w >= 0x20 && w <= 0x7E) || w == 0x09 || w == 0x0A || w == 0x0D;
    }

    inline std::string utf16le_to_ascii(const uint8_t* buf, const size_t chars)
    {
        std::string out;
        out.reserve(chars);

        for (size_t i = 0; i < chars; ++i)
            out.push_back(static_cast<char>(buf[i * 2]));

        return out;
    }

    inline void left_trim(std::string& s)
    {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](const unsigned char ch) { return !std::isspace(ch); }));
    }

    inline void right_trim(std::string& s)
    {
        s.erase(std::find_if(s.rbegin(), s.rend(), [](const unsigned char ch) { return !std::isspace(ch); }).base(),
                s.end());
    }

    inline std::string format_duration(const std::chrono::nanoseconds duration)
    {
        using namespace std::chrono;

        const auto ms_total = duration_cast<milliseconds>(duration).count();
        const auto hours = ms_total / (1000 * 60 * 60);
        const auto minutes = (ms_total / (1000 * 60)) % 60;
        const auto seconds = (ms_total / 1000) % 60;
        const auto millis = ms_total % 1000;

        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(2) << hours << ":" << std::setw(2) << minutes << ":" << std::setw(2)
            << seconds << "." << std::setw(3) << millis;
        return oss.str();
    }
}
