#pragma once

namespace instruction_classifier
{
    template <size_t N> constexpr bool contains(const std::array<int, N>& values, int itype) noexcept
    {
        for (const int value : values)
        {
            if (value == itype)
                return true;
        }

        return false;
    }

    constexpr bool is_branch(int itype) noexcept
    {
        constexpr auto jcc = std::to_array<int>(
            {NN_ja,  NN_jae,  NN_jb,  NN_jbe,  NN_jc,  NN_je,  NN_jz,  NN_jg,   NN_jge,  NN_jl,    NN_jle,
             NN_jna, NN_jnae, NN_jnb, NN_jnbe, NN_jnc, NN_jne, NN_jng, NN_jnge, NN_jnl,  NN_jnle,  NN_jno,
             NN_jnp, NN_jns,  NN_jnz, NN_jo,   NN_jp,  NN_jpe, NN_jpo, NN_js,   NN_jcxz, NN_jecxz, NN_jrcxz});

        return contains(jcc, itype);
    }

    constexpr bool is_flag_dependent(int itype) noexcept
    {
        constexpr auto flag_ops = std::to_array<int>(
            {NN_cmova,  NN_cmovb,  NN_cmovbe, NN_cmovg, NN_cmovge, NN_cmovl, NN_cmovle, NN_cmovno, NN_cmovnp,
             NN_cmovns, NN_cmovnz, NN_cmovo,  NN_cmovp, NN_cmovs,  NN_cmovz, NN_seta,   NN_setae,  NN_setb,
             NN_setbe,  NN_setc,   NN_sete,   NN_setg,  NN_setge,  NN_setl,  NN_setle,  NN_setne,  NN_setno,
             NN_setnp,  NN_setns,  NN_setnz,  NN_seto,  NN_setp,   NN_setpo, NN_sets,   NN_setz});

        return contains(flag_ops, itype);
    }

    constexpr bool is_conditional(int itype) noexcept
    {
        return is_branch(itype) || is_flag_dependent(itype);
    }

    constexpr bool should_dump(int itype) noexcept
    {
        constexpr auto ignored = std::to_array<int>({NN_mov, NN_xor, NN_push, NN_pop});
        return !contains(ignored, itype);
    }

    constexpr bool should_skip(int itype) noexcept
    {
        constexpr auto skip = std::to_array<int>(
            {NN_int3,    NN_hlt,     NN_ud2,    NN_syscall, NN_sysret, NN_vmcall, NN_vmclear, NN_vmlaunch, NN_vmresume,
             NN_vmptrld, NN_vmptrst, NN_vmread, NN_vmwrite, NN_vmxoff, NN_vmxon,  NN_clgi,    NN_invlpga,  NN_skinit,
             NN_stgi,    NN_vmexit,  NN_vmload, NN_vmmcall, NN_vmrun,  NN_vmsave, NN_invept,  NN_invvpid});

        return contains(skip, itype);
    }

    constexpr bool should_handle(int itype) noexcept
    {
        constexpr auto handle = std::to_array<int>({NN_vmovdqu, NN_vmovdqa, NN_vpxor, NN_vzeroupper});
        return contains(handle, itype);
    }
}
