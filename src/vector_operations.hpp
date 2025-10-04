#pragma once

namespace vector_operations
{
    inline uint64_t calculate_effective_address(uc_engine* uc, const op_t& op)
    {
        if (op.type != o_mem && op.type != o_displ)
            return 0;

        uint64_t ea = op.addr;
        const int base_reg = register_mapper::ida_to_unicorn(op.reg);

        if (base_reg != 0)
        {
            uint64_t base_val = 0;
            if (uc_reg_read(uc, base_reg, &base_val) == UC_ERR_OK)
                ea += base_val;
        }

        return ea;
    }

    inline bool read_vector_register(uc_engine* uc, int ida_reg, uint8_t* data, int expected_size)
    {
        if (register_mapper::is_xmm_reg(ida_reg) && expected_size >= 16)
        {
            const int xmm_reg = register_mapper::xmm_to_unicorn(ida_reg);
            return xmm_reg != 0 && uc_reg_read(uc, xmm_reg, data) == UC_ERR_OK;
        }

        if (register_mapper::is_ymm_reg(ida_reg) && expected_size >= 32)
        {
            const int ymm_reg = register_mapper::ymm_to_unicorn(ida_reg);
            return ymm_reg != 0 && uc_reg_read(uc, ymm_reg, data) == UC_ERR_OK;
        }

        return false;
    }

    inline bool write_vector_register(uc_engine* uc, int ida_reg, const uint8_t* data, int data_size)
    {
        if (register_mapper::is_xmm_reg(ida_reg))
        {
            const int xmm_reg = register_mapper::xmm_to_unicorn(ida_reg);
            if (xmm_reg == 0)
                return false;

            if (data_size == 32)
            {
                const int reg_num = register_mapper::xmm_number(ida_reg);
                if (reg_num < 0)
                    return false;

                const int ymm_reg = UC_X86_REG_YMM0 + reg_num;
                return uc_reg_write(uc, ymm_reg, data) == UC_ERR_OK;
            }

            return uc_reg_write(uc, xmm_reg, data) == UC_ERR_OK;
        }

        if (!register_mapper::is_ymm_reg(ida_reg))
            return false;

        const int ymm_reg = register_mapper::ymm_to_unicorn(ida_reg);
        if (ymm_reg == 0)
            return false;

        std::array<uint8_t, 32> ymm_data{};
        const size_t copy_size = std::min(static_cast<size_t>(data_size), ymm_data.size());
        std::copy_n(data, copy_size, ymm_data.data());

        return uc_reg_write(uc, ymm_reg, ymm_data.data()) == UC_ERR_OK;
    }

    template <typename Operation> inline void vmov_operation(uc_engine* uc, const insn_t& insn, Operation&& op)
    {
        std::array<uint8_t, 32> data{};

        if (insn.Op1.type == o_reg && (insn.Op2.type == o_mem || insn.Op2.type == o_displ))
        {
            const uint64_t mem_addr = calculate_effective_address(uc, insn.Op2);
            const int data_size = register_mapper::vector_reg_size(insn.Op1.reg);

            if (data_size > 0 && uc_mem_read(uc, mem_addr, data.data(), data_size) == UC_ERR_OK)
                write_vector_register(uc, insn.Op1.reg, data.data(), data_size);
        }
        else if ((insn.Op1.type == o_mem || insn.Op1.type == o_displ) && insn.Op2.type == o_reg)
        {
            const uint64_t mem_addr = calculate_effective_address(uc, insn.Op1);
            const int data_size = register_mapper::vector_reg_size(insn.Op2.reg);

            if (data_size > 0 && read_vector_register(uc, insn.Op2.reg, data.data(), data_size))
                uc_mem_write(uc, mem_addr, data.data(), data_size);
        }
        else if (insn.Op1.type == o_reg && insn.Op2.type == o_reg)
        {
            const int src_size = register_mapper::vector_reg_size(insn.Op2.reg);

            if (src_size > 0 && read_vector_register(uc, insn.Op2.reg, data.data(), src_size))
                write_vector_register(uc, insn.Op1.reg, data.data(), src_size);
        }
    }

    inline void update_rip(uc_engine* uc, uint64_t address, uint32_t size)
    {
        const uint64_t rip = address + size;
        uc_reg_write(uc, UC_X86_REG_RIP, &rip);
    }
}
