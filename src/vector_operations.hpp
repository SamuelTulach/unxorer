#pragma once

namespace vector_operations
{
    inline bool is_memory_operand(const op_t& op) noexcept
    {
        return op.type == o_mem || op.type == o_displ;
    }

    inline uint64_t calculate_effective_address(uc_engine* uc, const op_t& op)
    {
        if (!is_memory_operand(op))
            return 0;

        uint64_t ea = op.addr;
        const int base_reg = register_mapper::ida_to_unicorn(op.reg);
        if (base_reg == 0)
            return ea;

        uint64_t base_value = 0;
        if (uc_reg_read(uc, base_reg, &base_value) == UC_ERR_OK)
            ea += base_value;

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

    inline bool read_vector_operand(uc_engine* uc, const op_t& op, uint8_t* data, int expected_size)
    {
        if (is_memory_operand(op))
        {
            const uint64_t mem_addr = calculate_effective_address(uc, op);
            return uc_mem_read(uc, mem_addr, data, expected_size) == UC_ERR_OK;
        }

        if (op.type != o_reg)
            return false;

        const int reg_size = register_mapper::vector_reg_size(op.reg);
        return reg_size == expected_size && read_vector_register(uc, op.reg, data, expected_size);
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
                const int reg_index = register_mapper::xmm_number(ida_reg);
                if (reg_index < 0)
                    return false;

                return uc_reg_write(uc, UC_X86_REG_YMM0 + reg_index, data) == UC_ERR_OK;
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

    inline void vmov_operation(uc_engine* uc, const insn_t& insn)
    {
        std::array<uint8_t, 32> data{};

        if (insn.Op1.type == o_reg && is_memory_operand(insn.Op2))
        {
            const int size = register_mapper::vector_reg_size(insn.Op1.reg);
            if (size <= 0)
                return;

            if (read_vector_operand(uc, insn.Op2, data.data(), size))
                write_vector_register(uc, insn.Op1.reg, data.data(), size);
            return;
        }

        if (is_memory_operand(insn.Op1) && insn.Op2.type == o_reg)
        {
            const int size = register_mapper::vector_reg_size(insn.Op2.reg);
            if (size <= 0)
                return;

            const uint64_t mem_addr = calculate_effective_address(uc, insn.Op1);
            if (read_vector_operand(uc, insn.Op2, data.data(), size))
                uc_mem_write(uc, mem_addr, data.data(), size);
            return;
        }

        if (insn.Op1.type == o_reg && insn.Op2.type == o_reg)
        {
            const int size = register_mapper::vector_reg_size(insn.Op2.reg);
            if (size > 0 && read_vector_operand(uc, insn.Op2, data.data(), size))
                write_vector_register(uc, insn.Op1.reg, data.data(), size);
        }
    }

    inline void update_rip(uc_engine* uc, uint64_t address, uint32_t size)
    {
        const uint64_t rip = address + size;
        uc_reg_write(uc, UC_X86_REG_RIP, &rip);
    }
}
