#include "global.hpp"

namespace
{
    void handle_vmov(uc_engine* uc, const insn_t& insn)
    {
        vector_operations::vmov_operation(uc, insn);
    }

    void handle_vpxor(uc_engine* uc, const insn_t& insn)
    {
        if (insn.Op1.type != o_reg || insn.Op2.type != o_reg)
            return;

        const int data_size = register_mapper::vector_reg_size(insn.Op2.reg);
        if (data_size <= 0)
            return;

        std::array<uint8_t, 32> lhs{};
        std::array<uint8_t, 32> rhs{};
        if (!vector_operations::read_vector_register(uc, insn.Op2.reg, lhs.data(), data_size))
            return;

        if (!vector_operations::read_vector_operand(uc, insn.Op3, rhs.data(), data_size))
            return;

        std::array<uint8_t, 32> result{};
        for (int i = 0; i < data_size; ++i)
            result[i] = lhs[i] ^ rhs[i];

        vector_operations::write_vector_register(uc, insn.Op1.reg, result.data(), data_size);
    }

    void handle_vzeroupper(uc_engine* uc)
    {
        std::array<uint8_t, 32> ymm{};

        for (int i = 0; i < 16; ++i)
        {
            const int reg = UC_X86_REG_YMM0 + i;
            if (uc_reg_read(uc, reg, ymm.data()) != UC_ERR_OK)
                continue;

            std::fill(ymm.begin() + 16, ymm.end(), 0);
            uc_reg_write(uc, reg, ymm.data());
        }
    }
}

void handler::handle(uc_engine* uc, const uint64_t address, const uint32_t size, const insn_t& insn)
{
    vector_operations::update_rip(uc, address, size);
    logger::debug("custom handling at {0:x} with size {1:d}...", address, size);

    switch (insn.itype)
    {
    case NN_vmovdqu:
    case NN_vmovdqa:
        handle_vmov(uc, insn);
        break;

    case NN_vpxor:
        handle_vpxor(uc, insn);
        break;

    case NN_vzeroupper:
        handle_vzeroupper(uc);
        break;

    default:
        break;
    }
}
