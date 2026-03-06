#pragma once

namespace register_mapper
{
    constexpr bool in_range(int value, int min, int max) noexcept
    {
        return value >= min && value <= max;
    }

    constexpr int ida_to_unicorn(int ida_reg) noexcept
    {
        constexpr auto mapping = std::to_array<int>({UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
                                                     UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                                                     UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
                                                     UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15});

        if (!in_range(ida_reg, 0, static_cast<int>(mapping.size() - 1)))
            return 0;

        return mapping[ida_reg];
    }

    constexpr bool is_xmm_reg(int reg_num) noexcept
    {
        return in_range(reg_num, 16, 31) || in_range(reg_num, 64, 79);
    }

    constexpr bool is_ymm_reg(int reg_num) noexcept
    {
        return in_range(reg_num, 81, 96);
    }

    constexpr int xmm_number(int ida_reg) noexcept
    {
        if (in_range(ida_reg, 16, 31))
            return ida_reg - 16;

        if (in_range(ida_reg, 64, 79))
            return ida_reg - 64;

        return -1;
    }

    constexpr int ymm_number(int ida_reg) noexcept
    {
        return is_ymm_reg(ida_reg) ? ida_reg - 81 : -1;
    }

    constexpr int xmm_to_unicorn(int ida_reg) noexcept
    {
        const int index = xmm_number(ida_reg);
        return index >= 0 ? UC_X86_REG_XMM0 + index : 0;
    }

    constexpr int ymm_to_unicorn(int ida_reg) noexcept
    {
        const int index = ymm_number(ida_reg);
        return index >= 0 ? UC_X86_REG_YMM0 + index : 0;
    }

    constexpr int vector_reg_size(int reg_num) noexcept
    {
        if (is_xmm_reg(reg_num))
            return 16;

        if (is_ymm_reg(reg_num))
            return 32;

        return 0;
    }
}
