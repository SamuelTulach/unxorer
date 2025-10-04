#pragma once

namespace register_mapper
{
    constexpr int ida_to_unicorn(int ida_reg) noexcept
    {
        constexpr int mapping[] = {UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
                                   UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                                   UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
                                   UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15};

        if (ida_reg >= 0 && ida_reg < 16)
            return mapping[ida_reg];

        return 0;
    }

    constexpr bool is_xmm_reg(int reg_num) noexcept
    {
        return (reg_num >= 16 && reg_num <= 31) || (reg_num >= 64 && reg_num <= 79);
    }

    constexpr bool is_ymm_reg(int reg_num) noexcept
    {
        return reg_num >= 81 && reg_num <= 96;
    }

    constexpr int xmm_number(int ida_reg) noexcept
    {
        if (ida_reg >= 16 && ida_reg <= 31)
            return ida_reg - 16;

        if (ida_reg >= 64 && ida_reg <= 79)
            return ida_reg - 64;

        return -1;
    }

    constexpr int ymm_number(int ida_reg) noexcept
    {
        if (is_ymm_reg(ida_reg))
            return ida_reg - 81;

        return -1;
    }

    constexpr int xmm_to_unicorn(int ida_reg) noexcept
    {
        const int num = xmm_number(ida_reg);
        return num >= 0 ? UC_X86_REG_XMM0 + num : 0;
    }

    constexpr int ymm_to_unicorn(int ida_reg) noexcept
    {
        const int num = ymm_number(ida_reg);
        return num >= 0 ? UC_X86_REG_YMM0 + num : 0;
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
