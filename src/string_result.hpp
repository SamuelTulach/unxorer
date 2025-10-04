#pragma once

struct found_string_t
{
    uint64_t rip = 0;
    uint64_t rsp = 0;
    std::string data;

    bool operator==(const found_string_t& other) const noexcept
    {
        return data == other.data;
    }
};

struct found_string_hash
{
    size_t operator()(const found_string_t& input) const noexcept
    {
        return std::hash<std::string>{}(input.data);
    }
};
