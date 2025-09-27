#include "global.hpp"

static int ida_reg_to_unicorn(const int ida_reg)
{
    switch (ida_reg)
    {
    case 0:
        return UC_X86_REG_RAX;
    case 1:
        return UC_X86_REG_RCX;
    case 2:
        return UC_X86_REG_RDX;
    case 3:
        return UC_X86_REG_RBX;
    case 4:
        return UC_X86_REG_RSP;
    case 5:
        return UC_X86_REG_RBP;
    case 6:
        return UC_X86_REG_RSI;
    case 7:
        return UC_X86_REG_RDI;
    case 8:
        return UC_X86_REG_R8;
    case 9:
        return UC_X86_REG_R9;
    case 10:
        return UC_X86_REG_R10;
    case 11:
        return UC_X86_REG_R11;
    case 12:
        return UC_X86_REG_R12;
    case 13:
        return UC_X86_REG_R13;
    case 14:
        return UC_X86_REG_R14;
    case 15:
        return UC_X86_REG_R15;
    default:
        return 0;
    }
}

static bool is_valid_xmm_reg(const int reg_num)
{
    return (reg_num >= 16 && reg_num <= 31) || (reg_num >= 64 && reg_num <= 79);
}

static bool is_valid_ymm_reg(const int reg_num)
{
    return reg_num >= 81 && reg_num <= 96;
}

static int get_unicorn_xmm_reg(const int ida_reg)
{
    if (ida_reg >= 16 && ida_reg <= 31)
        return UC_X86_REG_XMM0 + (ida_reg - 16);

    if (ida_reg >= 64 && ida_reg <= 79)
        return UC_X86_REG_XMM0 + (ida_reg - 64);

    return 0;
}

static int get_unicorn_ymm_reg(const int ida_reg)
{
    if (is_valid_ymm_reg(ida_reg))
        return UC_X86_REG_YMM0 + (ida_reg - 81);
    return 0;
}

static int get_xmm_register_number(const int ida_reg)
{
    if (ida_reg >= 16 && ida_reg <= 31)
        return ida_reg - 16;

    if (ida_reg >= 64 && ida_reg <= 79)
        return ida_reg - 64;

    return -1;
}

static int get_ymm_register_number(const int ida_reg)
{
    if (is_valid_ymm_reg(ida_reg))
        return ida_reg - 81;
    return -1;
}

static int get_vector_reg_size(const int reg_num)
{
    if (is_valid_xmm_reg(reg_num))
        return 16;
    if (is_valid_ymm_reg(reg_num))
        return 32;
    return 0;
}

static uint64_t calculate_effective_address(uc_engine* uc, const op_t& op)
{
    uint64_t ea = 0;

    if (op.type != o_mem && op.type != o_displ)
        return ea;

    ea = op.addr;

    const int base_reg = ida_reg_to_unicorn(op.reg);
    if (!base_reg)
        return ea;

    uint64_t base_val = 0;
    if (uc_reg_read(uc, base_reg, &base_val) == UC_ERR_OK)
        ea += base_val;

    return ea;
}

static void update_rip(uc_engine* uc, const uint64_t address, const uint32_t size)
{
    const uint64_t rip = address + size;
    uc_reg_write(uc, UC_X86_REG_RIP, &rip);
}

static bool read_vector_register(uc_engine* uc, const int ida_reg, uint8_t* data, const int expected_size)
{
    if (is_valid_xmm_reg(ida_reg) && expected_size >= 16)
    {
        const int xmm_reg = get_unicorn_xmm_reg(ida_reg);
        if (!xmm_reg)
            return false;

        return uc_reg_read(uc, xmm_reg, data) == UC_ERR_OK;
    }

    if (is_valid_ymm_reg(ida_reg) && expected_size >= 32)
    {
        const int ymm_reg = get_unicorn_ymm_reg(ida_reg);
        if (!ymm_reg)
            return false;

        return uc_reg_read(uc, ymm_reg, data) == UC_ERR_OK;
    }

    return false;
}

static bool write_vector_register(uc_engine* uc, const int ida_reg, const uint8_t* data, const int data_size)
{
    if (is_valid_xmm_reg(ida_reg))
    {
        const int xmm_reg = get_unicorn_xmm_reg(ida_reg);
        if (!xmm_reg)
            return false;

        if (data_size == 32)
        {
            const int reg_num = get_xmm_register_number(ida_reg);
            if (reg_num < 0)
                return false;

            const int ymm_reg = UC_X86_REG_YMM0 + reg_num;
            return uc_reg_write(uc, ymm_reg, data) == UC_ERR_OK;
        }

        return uc_reg_write(uc, xmm_reg, data) == UC_ERR_OK;
    }

    if (!is_valid_ymm_reg(ida_reg))
        return false;

    const int ymm_reg = get_unicorn_ymm_reg(ida_reg);
    if (!ymm_reg)
        return false;

    uint8_t ymm_data[32] = {0};
    if (data_size > 32)
        return false;

    memcpy(ymm_data, data, data_size);
    if (data_size < 32)
        memset(ymm_data + data_size, 0, 32 - data_size);

    return uc_reg_write(uc, ymm_reg, ymm_data) == UC_ERR_OK;
}

void handler::vmovdqu(uc_engine* uc, const uint64_t address, const uint32_t size, insn_t insn)
{
    uint8_t data[32] = {0};

    if (insn.Op1.type == o_reg && (insn.Op2.type == o_mem || insn.Op2.type == o_displ))
    {
        const uint64_t mem_addr = calculate_effective_address(uc, insn.Op2);
        const int data_size = get_vector_reg_size(insn.Op1.reg);

        if (data_size <= 0 || uc_mem_read(uc, mem_addr, data, data_size) != UC_ERR_OK)
            return;

        write_vector_register(uc, insn.Op1.reg, data, data_size);
    }
    else if ((insn.Op1.type == o_mem || insn.Op1.type == o_displ) && insn.Op2.type == o_reg)
    {
        const uint64_t mem_addr = calculate_effective_address(uc, insn.Op1);
        const int data_size = get_vector_reg_size(insn.Op2.reg);

        if (data_size <= 0 || !read_vector_register(uc, insn.Op2.reg, data, data_size))
            return;

        uc_mem_write(uc, mem_addr, data, data_size);
    }
    else if (insn.Op1.type == o_reg && insn.Op2.type == o_reg)
    {
        const int src_size = get_vector_reg_size(insn.Op2.reg);
        if (src_size <= 0 || !read_vector_register(uc, insn.Op2.reg, data, src_size))
            return;

        write_vector_register(uc, insn.Op1.reg, data, src_size);
    }
}

void handler::vmovdqa(uc_engine* uc, const uint64_t address, const uint32_t size, insn_t insn)
{
    uint8_t data[32] = {0};

    if (insn.Op1.type == o_reg && (insn.Op2.type == o_mem || insn.Op2.type == o_displ))
    {
        const uint64_t mem_addr = calculate_effective_address(uc, insn.Op2);
        const int data_size = get_vector_reg_size(insn.Op1.reg);

        if (data_size <= 0 || uc_mem_read(uc, mem_addr, data, data_size) != UC_ERR_OK)
            return;

        write_vector_register(uc, insn.Op1.reg, data, data_size);
    }
    else if ((insn.Op1.type == o_mem || insn.Op1.type == o_displ) && insn.Op2.type == o_reg)
    {
        const uint64_t mem_addr = calculate_effective_address(uc, insn.Op1);
        const int data_size = get_vector_reg_size(insn.Op2.reg);

        if (data_size <= 0 || !read_vector_register(uc, insn.Op2.reg, data, data_size))
            return;

        uc_mem_write(uc, mem_addr, data, data_size);
    }
    else if (insn.Op1.type == o_reg && insn.Op2.type == o_reg)
    {
        const int src_size = get_vector_reg_size(insn.Op2.reg);
        if (src_size <= 0 || !read_vector_register(uc, insn.Op2.reg, data, src_size))
            return;

        write_vector_register(uc, insn.Op1.reg, data, src_size);
    }
}

void handler::vpxor(uc_engine* uc, const uint64_t address, const uint32_t size, insn_t insn)
{
    uint8_t src1_data[32] = {0};
    uint8_t src2_data[32] = {0};
    uint8_t result_data[32] = {0};

    if (insn.Op2.type != o_reg)
        return;

    const int data_size = get_vector_reg_size(insn.Op2.reg);
    if (data_size <= 0 || !read_vector_register(uc, insn.Op2.reg, src1_data, data_size))
        return;

    bool valid_src2 = false;
    if (insn.Op3.type == o_mem || insn.Op3.type == o_displ)
    {
        const uint64_t mem_addr = calculate_effective_address(uc, insn.Op3);
        valid_src2 = (uc_mem_read(uc, mem_addr, src2_data, data_size) == UC_ERR_OK);
    }
    else if (insn.Op3.type == o_reg)
    {
        const int src3_size = get_vector_reg_size(insn.Op3.reg);
        valid_src2 = (src3_size == data_size && read_vector_register(uc, insn.Op3.reg, src2_data, data_size));
    }

    if (!valid_src2)
        return;

    for (int i = 0; i < data_size; i++)
        result_data[i] = src1_data[i] ^ src2_data[i];

    if (insn.Op1.type != o_reg)
        return;

    write_vector_register(uc, insn.Op1.reg, result_data, data_size);
}

void handler::vzeroupper(uc_engine* uc, const uint64_t address, const uint32_t size, insn_t insn)
{
    for (int i = 0; i < 16; i++)
    {
        const int ymm_reg = UC_X86_REG_YMM0 + i;
        uint8_t ymm_data[32] = {0};

        if (uc_reg_read(uc, ymm_reg, ymm_data) != UC_ERR_OK)
            continue;

        memset(&ymm_data[16], 0, 16);
        uc_reg_write(uc, ymm_reg, ymm_data);
    }
}

void handler::handle(uc_engine* uc, uint64_t address, uint32_t size, insn_t insn)
{
    update_rip(uc, address, size);
    logger::print("custom handling at {0:x} with size {1:d}...", address, size);

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