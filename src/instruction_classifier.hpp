#pragma once

namespace instruction_classifier
{
    constexpr bool is_conditional(int itype) noexcept
    {
        constexpr int jcc[] = {NN_ja,   NN_jae, NN_jb,   NN_jbe,  NN_jc,    NN_je,   NN_jz,  NN_jg,  NN_jge,
                               NN_jl,   NN_jle, NN_jna,  NN_jnae, NN_jnb,   NN_jnbe, NN_jnc, NN_jne, NN_jng,
                               NN_jnge, NN_jnl, NN_jnle, NN_jno,  NN_jnp,   NN_jns,  NN_jnz, NN_jo,  NN_jp,
                               NN_jpe,  NN_jpo, NN_js,   NN_jcxz, NN_jecxz, NN_jrcxz};

        for (const auto type : jcc)
        {
            if (type == itype)
                return true;
        }

        return false;
    }

    constexpr bool should_dump(int itype) noexcept
    {
        constexpr int ignored[] = {NN_mov, NN_xor, NN_push, NN_pop};

        for (const auto type : ignored)
        {
            if (type == itype)
                return false;
        }

        return true;
    }

    constexpr bool should_skip(int itype) noexcept
    {
        constexpr int skip[] = {NN_int3,     NN_hlt,      NN_ud2,     NN_syscall, NN_sysret, NN_vmcall,  NN_vmclear,
                                NN_vmlaunch, NN_vmresume, NN_vmptrld, NN_vmptrst, NN_vmread, NN_vmwrite, NN_vmxoff,
                                NN_vmxon,    NN_clgi,     NN_invlpga, NN_skinit,  NN_stgi,   NN_vmexit,  NN_vmload,
                                NN_vmmcall,  NN_vmrun,    NN_vmsave,  NN_invept,  NN_invvpid};

        for (const auto type : skip)
        {
            if (type == itype)
                return true;
        }

        return false;
    }

    constexpr bool should_handle(int itype) noexcept
    {
        constexpr int handle[] = {NN_vmovdqu, NN_vmovdqa, NN_vpxor, NN_vzeroupper};

        for (const auto type : handle)
        {
            if (type == itype)
                return true;
        }

        return false;
    }
}
