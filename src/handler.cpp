#include "global.hpp"

void handler::vmovdqu(uc_engine* uc, const uint64_t address, const uint32_t size, const insn_t& insn)
{
    vector_operations::vmov_operation(uc, insn, [](auto&&...) {});
}

void handler::vmovdqa(uc_engine* uc, const uint64_t address, const uint32_t size, const insn_t& insn)
{
    vector_operations::vmov_operation(uc, insn, [](auto&&...) {});
}

void handler::vpxor(uc_engine* uc, const uint64_t address, const uint32_t size, const insn_t& insn)
{
    if (insn.Op2.type != o_reg)
        return;

    const int data_size = register_mapper::vector_reg_size(insn.Op2.reg);
    if (data_size <= 0)
        return;

    std::array<uint8_t, 32> src1_data{};
    std::array<uint8_t, 32> src2_data{};

    if (!vector_operations::read_vector_register(uc, insn.Op2.reg, src1_data.data(), data_size))
        return;

    bool valid_src2 = false;
    if (insn.Op3.type == o_mem || insn.Op3.type == o_displ)
    {
        const uint64_t mem_addr = vector_operations::calculate_effective_address(uc, insn.Op3);
        valid_src2 = (uc_mem_read(uc, mem_addr, src2_data.data(), data_size) == UC_ERR_OK);
    }
    else if (insn.Op3.type == o_reg)
    {
        const int src3_size = register_mapper::vector_reg_size(insn.Op3.reg);
        valid_src2 = (src3_size == data_size &&
                      vector_operations::read_vector_register(uc, insn.Op3.reg, src2_data.data(), data_size));
    }

    if (!valid_src2 || insn.Op1.type != o_reg)
        return;

    std::array<uint8_t, 32> result_data{};
    for (int i = 0; i < data_size; i++)
        result_data[i] = src1_data[i] ^ src2_data[i];

    vector_operations::write_vector_register(uc, insn.Op1.reg, result_data.data(), data_size);
}

void handler::vzeroupper(uc_engine* uc, const uint64_t address, const uint32_t size, const insn_t& insn)
{
    std::array<uint8_t, 32> ymm_data{};

    for (int i = 0; i < 16; i++)
    {
        const int ymm_reg = UC_X86_REG_YMM0 + i;

        if (uc_reg_read(uc, ymm_reg, ymm_data.data()) != UC_ERR_OK)
            continue;

        std::fill(ymm_data.begin() + 16, ymm_data.end(), 0);
        uc_reg_write(uc, ymm_reg, ymm_data.data());
    }
}

void handler::handle(uc_engine* uc, const uint64_t address, const uint32_t size, const insn_t& insn)
{
    vector_operations::update_rip(uc, address, size);
    logger::debug("custom handling at {0:x} with size {1:d}...", address, size);

    switch (insn.itype)
    {
    case NN_vmovdqu:
        vmovdqu(uc, address, size, insn);
        break;
    case NN_vmovdqa:
        vmovdqa(uc, address, size, insn);
        break;
    case NN_vpxor:
        vpxor(uc, address, size, insn);
        break;
    case NN_vzeroupper:
        vzeroupper(uc, address, size, insn);
        break;
    default:
        break;
    }
}