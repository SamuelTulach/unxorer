#include "global.hpp"

void emulator::overwrite_all_registers(const uint64_t value)
{
    if (uc_reg_write(engine, UC_X86_REG_RAX, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_RBX, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_RCX, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_RDX, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_RSI, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_RDI, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_RBP, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_RSP, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_R8, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_R9, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_R10, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_R11, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_R12, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_R13, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_R14, &value) != UC_ERR_OK ||
        uc_reg_write(engine, UC_X86_REG_R15, &value) != UC_ERR_OK)
    {
        logger::print("failed to overwrite registers");
    }
}

void emulator::print_disasm(const ea_t& address)
{
    qstring line;
    generate_disasm_line(&line, address, GENDSM_REMOVE_TAGS);
    tag_remove(&line);
    logger::print("{0:x}: {1}", address, line.c_str());
}

void emulator::push_string(const uint64_t rip, const uint64_t rsp, const std::string& str)
{
    if (str.empty())
        return;

    std::string escaped;
    escaped.reserve(str.size());

    for (const unsigned char c : str)
    {
        switch (c)
        {
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        case '\v':
            escaped += "\\v";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\a':
            escaped += "\\a";
            break;
        case '\b':
            escaped += "\\b";
            break;
        default:
            escaped += static_cast<char>(c);
        }
    }

    strings::left_trim(escaped);
    strings::right_trim(escaped);

    found_string_t found_string;
    found_string.rip = rip;
    found_string.rsp = rsp;
    found_string.data = std::move(escaped);

    string_list.emplace(found_string);
}

void emulator::dump_stack_strings()
{
    uint64_t rsp = 0;
    uc_reg_read(engine, UC_X86_REG_RSP, &rsp);

    uint64_t rip = 0;
    uc_reg_read(engine, UC_X86_REG_RIP, &rip);

    // logger::print("dumping stack strings with rsp {0:x}...", rsp);

    if (rsp < stack_base - stack_size || rsp >= stack_base)
    {
        logger::print("rsp {0:x} is out of stack bounds ({1:x} - {2:x})", rsp, stack_base - stack_size, stack_base);
        return;
    }

    size_t scan_sz = stack_base - rsp;
    const size_t max_scan = 0x20000;
    scan_sz = min(scan_sz, max_scan);

    std::vector<uint8_t> buf(scan_sz);
    if (uc_mem_read(engine, rsp, buf.data(), scan_sz) != UC_ERR_OK)
    {
        logger::print("failed to read stack memory at {0:x} with size {1:x}", rsp, scan_sz);
        return;
    }

    for (size_t i = 0; i < scan_sz;)
    {
        if (strings::is_ascii_printable(buf[i]))
        {
            size_t j = i;
            while (j < scan_sz && strings::is_ascii_printable(buf[j]))
                ++j;

            if (j - i >= 4 && j < scan_sz && buf[j] == 0)
            {
                std::string s(reinterpret_cast<char*>(&buf[i]), j - i);
                push_string(rip, rsp - (i + 1), s);
            }

            i = j + 1;
            continue;
        }

        if (i + 3 < scan_sz && strings::is_utf16_printable(*reinterpret_cast<const uint16_t*>(&buf[i])))
        {
            size_t j = i;
            while (j + 1 < scan_sz && strings::is_utf16_printable(*reinterpret_cast<const uint16_t*>(&buf[j])))
                j += 2;

            if ((j - i) / 2 >= 4 && j + 1 < scan_sz && buf[j] == 0 && buf[j + 1] == 0)
            {
                std::string s = strings::utf16le_to_ascii(&buf[i], (j - i) / 2);
                push_string(rip, rsp - (i + 2), s);
            }

            i = j + 2;
            continue;
        }

        ++i;
    }
}

bool emulator::is_conditional(const insn_t& insn)
{
    static const std::unordered_set<int> jcc = {
        NN_ja,  NN_jae,  NN_jb,  NN_jbe,  NN_jc,  NN_je,  NN_jz,  NN_jg,   NN_jge,  NN_jl,    NN_jle,
        NN_jna, NN_jnae, NN_jnb, NN_jnbe, NN_jnc, NN_jne, NN_jng, NN_jnge, NN_jnl,  NN_jnle,  NN_jno,
        NN_jnp, NN_jns,  NN_jnz, NN_jo,   NN_jp,  NN_jpe, NN_jpo, NN_js,   NN_jcxz, NN_jecxz, NN_jrcxz};
    return jcc.contains(insn.itype);
}

bool emulator::should_dump(const insn_t& insn)
{
    static const std::unordered_set<int> ignored = {NN_mov, NN_xor, NN_push, NN_pop};
    return !ignored.contains(insn.itype);
}

bool emulator::should_skip(const insn_t& insn)
{
    static const std::unordered_set<int> skip = {
        NN_int3,    NN_hlt,     NN_ud2,    NN_syscall, NN_sysret, NN_vmcall, NN_vmclear, NN_vmlaunch, NN_vmresume,
        NN_vmptrld, NN_vmptrst, NN_vmread, NN_vmwrite, NN_vmxoff, NN_vmxon,  NN_clgi,    NN_invlpga,  NN_skinit,
        NN_stgi,    NN_vmexit,  NN_vmload, NN_vmmcall, NN_vmrun,  NN_vmsave, NN_invept,  NN_invvpid};
    return skip.contains(insn.itype);
}

void emulator::force_branch(uc_engine* uc, const insn_t& insn)
{
    constexpr uint64_t f_cf = 0x00000001ull;
    constexpr uint64_t f_pf = 0x00000004ull;
    constexpr uint64_t f_zf = 0x00000040ull;
    constexpr uint64_t f_sf = 0x00000080ull;
    constexpr uint64_t f_of = 0x00000800ull;

    uint64_t eflags = 0;
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);

    auto set = [&](const uint64_t mask) { eflags |= mask; };
    auto clear = [&](const uint64_t mask) { eflags &= ~mask; };

    switch (insn.itype)
    {
    case NN_jz:
    case NN_je:
        set(f_zf);
        break;
    case NN_jnz:
    case NN_jne:
        clear(f_zf);
        break;

    case NN_jc:
    case NN_jb:
    case NN_jnae:
        set(f_cf);
        break;
    case NN_jnc:
    case NN_jnb:
    case NN_jae:
        clear(f_cf);
        break;

    case NN_js:
        set(f_sf);
        break;
    case NN_jns:
        clear(f_sf);
        break;

    case NN_jo:
        set(f_of);
        break;
    case NN_jno:
        clear(f_of);
        break;

    case NN_jp:
    case NN_jpe:
        set(f_pf);
        break;
    case NN_jnp:
    case NN_jpo:
        clear(f_pf);
        break;

    case NN_ja:
    case NN_jnbe:
        clear(f_cf | f_zf);
        break;
    case NN_jbe:
    case NN_jna:
        set(f_cf);
        break;

    case NN_jg:
    case NN_jnle:
        clear(f_zf | f_sf | f_of);
        break;
    case NN_jge:
    case NN_jnl:
        clear(f_sf | f_of);
        break;
    case NN_jl:
    case NN_jnge:
        set(f_sf);
        clear(f_of);
        break;
    case NN_jle:
    case NN_jng:
        set(f_zf);
        break;

    case NN_jcxz:
    case NN_jecxz:
    case NN_jrcxz: {
        const uint64_t rcx = 0;
        uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    }
    break;

    default:
        break;
    }

    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);
}

bool emulator::is_external_thunk(ea_t ea)
{
    insn_t jmp;
    if (!decode_insn(&jmp, ea))
        return false;

    constexpr int jmp_types[] = {NN_jmp, NN_jmpfi, NN_jmpni};
    if (std::find(std::begin(jmp_types), std::end(jmp_types), jmp.itype) == std::end(jmp_types))
        return false;

    ea_t img_min = inf_get_min_ea();
    ea_t img_max = inf_get_max_ea();

    uint64_t final = 0;
    bool have_final = false;

    switch (jmp.Op1.type)
    {
    case o_near:
    case o_far:
        final = jmp.Op1.addr;
        have_final = true;
        break;

    case o_mem:
    case o_displ:
        if (uc_mem_read(engine, jmp.Op1.addr, &final, sizeof(final)) == UC_ERR_OK)
            have_final = true;
        break;

    default:
        break;
    }

    return have_final && (final < img_min || final >= img_max);
}

bool emulator::handle_call(uc_engine* uc, uint64_t address, uint32_t size, insn_t insn)
{
    if (insn.itype != NN_call && insn.itype != NN_callfi && insn.itype != NN_callni)
        return false;

    const ea_t img_min = inf_get_min_ea();
    const ea_t img_max = inf_get_max_ea();

    uint64_t dest = 0;
    bool have_dest = false;

    switch (insn.Op1.type)
    {
    case o_near:
    case o_far:
        dest = insn.Op1.addr;
        have_dest = true;
        break;

    case o_mem:
    case o_displ: {
        const uint64_t ptr_addr = insn.Op1.addr;
        if (uc_mem_read(uc, ptr_addr, &dest, sizeof(dest)) == UC_ERR_OK)
            have_dest = true;
        break;
    }

    default:
        break;
    }

    bool external = have_dest && (dest < img_min || dest >= img_max);
    if (!external && have_dest && is_external_thunk(dest))
    {
        ++counters::import_thunks;
        external = true;
    }

    if (!external)
        return false;

    const uint64_t new_rip = address + size;
    uc_reg_write(uc, UC_X86_REG_RIP, &new_rip);

    constexpr uint64_t zero = 0;
    uc_reg_write(uc, UC_X86_REG_RAX, &zero);

    ++counters::external_calls;
    return true;
}

void emulator::hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    insn_t insn;
    if (!decode_insn(&insn, address))
        return;

#ifndef NDEBUG
    print_disasm(address);
#endif

    ++counters::instructions_executed;

    if (should_update_dialog)
        replace_wait_box("Emulating at 0x%a, executed %zu instructions", address, counters::instructions_executed);

    if (should_skip(insn))
    {
        uint64_t rip = 0;
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        rip += size;
        uc_reg_write(uc, UC_X86_REG_RIP, &rip);

        ++counters::skipped;
        return;
    }

    if (should_dump(insn))
        dump_stack_strings();

    if (handle_call(uc, address, size, insn))
        return;

    if (!is_conditional(insn))
        return;

    const uint64_t taken = insn.Op1.addr;
    const uint64_t fallthrough = address + size;

    if (!visited.contains(fallthrough))
    {
        branch_state_t st;
        uc_context_alloc(uc, &st.ctx);
        uc_context_save(uc, st.ctx);
        st.pc = fallthrough;
        pending.push_back(std::move(st));
        ++counters::branched;
    }
    else
    {
        ++counters::already_visited;
    }

    visited.insert(fallthrough);

    if (taken > address)
        force_branch(engine, insn);
}

bool emulator::hook_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
    constexpr uint64_t page_mask = ~0xFFFULL;
    const uint64_t page = address & page_mask;

    if (uc_mem_map(uc, page, 0x1000, UC_PROT_ALL) != UC_ERR_OK)
        return false;

    uint64_t rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);

    logger::print("mapped missing page {0:x} for {1:x}, resuming...", page, rip);
    return true;
}

void emulator::reset()
{
    pending.clear();
    visited.clear();
    string_list.clear();

    counters::start_time.reset();
    counters::instructions_executed = 0;
    counters::branched = 0;
    counters::already_visited = 0;
    counters::skipped = 0;
    counters::external_calls = 0;
    counters::import_thunks = 0;

    should_update_dialog = true;
}

void emulator::run(ea_t start, uint64_t max_time_ms, uint64_t max_instr_branch)
{
    logger::print("starting emulation from {0:x}...", start);

    if (!counters::start_time.has_value())
        counters::start_time = std::chrono::high_resolution_clock::now();

    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &engine);
    if (err != UC_ERR_OK)
    {
        logger::print("failed to initialize engine: {0}", uc_strerror(err));
        return;
    }

    overwrite_all_registers(0x2000);

    constexpr uint64_t page_size = 0x1000;
    constexpr uint64_t page_mask = ~(page_size - 1);

    const ea_t img_min = inf_get_min_ea();
    const ea_t img_max = inf_get_max_ea();

    const uint64_t map_start = img_min & page_mask;
    const uint64_t map_end = (img_max + page_size - 1) & page_mask;
    const size_t map_size = map_end - map_start;

    err = uc_mem_map(engine, map_start, map_size, UC_PROT_ALL);
    if (err != UC_ERR_OK)
    {
        logger::print("failed to map memory range {0:x} to {1:x}: {2}", img_min, img_max, uc_strerror(err));
        uc_close(engine);
        return;
    }

    const size_t size = img_max - img_min;
    std::vector<uint8_t> buffer(size);
    const ssize_t got = get_bytes(buffer.data(), size, img_min, GMB_READALL);
    if (got <= 0)
    {
        logger::print("failed to read memory from {0:x} to {1:x}: {2}", img_min, img_max, got);
        uc_close(engine);
        return;
    }

    err = uc_mem_write(engine, img_min, buffer.data(), size);
    if (err != UC_ERR_OK)
    {
        logger::print("failed to write memory from {0:x} with size {1:x}: {2}", img_min, size, uc_strerror(err));
        uc_close(engine);
        return;
    }

    err = uc_mem_map(engine, stack_base - stack_size, stack_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK)
    {
        logger::print("failed to map stack: {0}", uc_strerror(err));
        uc_close(engine);
        return;
    }

    uc_reg_write(engine, UC_X86_REG_RSP, &stack_base);

    uc_hook_add(engine, &code_hook, UC_HOOK_CODE, hook_code, nullptr, 1, 0);
    uc_hook_add(engine, &mem_hook, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem, nullptr, 1, 0);

    uint64_t entry = start;

    for (;;)
    {
        uc_reg_write(engine, UC_X86_REG_RIP, &entry);

        err = uc_emu_start(engine, entry, 0, max_time_ms * 1000, max_instr_branch);
        if (err != UC_ERR_OK)
        {
            logger::print("emulation failure: {0}", uc_strerror(err));
        }

        if (pending.empty())
            break;

        const branch_state_t st = std::move(pending.back());
        pending.pop_back();

        uc_context_restore(engine, st.ctx);
        entry = st.pc;
    }

    uc_close(engine);
}
