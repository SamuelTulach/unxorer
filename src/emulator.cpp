#include "global.hpp"

void emulator::overwrite_all_registers(const uint64_t value) const
{
    constexpr int registers[] = {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                                 UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
                                 UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
                                 UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15};

    for (const auto reg : registers)
    {
        if (uc_reg_write(engine, reg, &value) != UC_ERR_OK)
        {
            logger::debug("failed to overwrite register");
            break;
        }
    }
}

void emulator::print_disasm(const ea_t address) const
{
    qstring line;
    generate_disasm_line(&line, address, GENDSM_REMOVE_TAGS);
    tag_remove(&line);
    logger::debug("{0:x}: {1}", address, line.c_str());
}

void emulator::push_string(const uint64_t rip, const uint64_t rsp, std::string str)
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

    string_list_.emplace(found_string_t{rip, rsp, std::move(escaped)});
}

void emulator::dump_stack_strings()
{
    uint64_t rsp = 0;
    uc_reg_read(engine, UC_X86_REG_RSP, &rsp);

    uint64_t rip = 0;
    uc_reg_read(engine, UC_X86_REG_RIP, &rip);

    if (rsp < stack_base - stack_size || rsp >= stack_base)
    {
        logger::debug("rsp {0:x} is out of stack bounds ({1:x} - {2:x})", rsp, stack_base - stack_size, stack_base);
        return;
    }

    constexpr size_t max_scan = 0x20000;
    size_t scan_sz = std::min(static_cast<size_t>(stack_base - rsp), max_scan);

    std::vector<uint8_t> buf(scan_sz);
    if (uc_mem_read(engine, rsp, buf.data(), scan_sz) != UC_ERR_OK)
    {
        logger::debug("failed to read stack memory at {0:x} with size {1:x}", rsp, scan_sz);
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
                push_string(rip, rsp - (i + 1), std::move(s));
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
                push_string(rip, rsp - (i + 2), std::move(s));
            }

            i = j + 2;
            continue;
        }

        ++i;
    }
}

void emulator::force_branch(uc_engine* uc, const insn_t& insn) const
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

bool emulator::is_external_thunk(const ea_t ea) const
{
    insn_t jmp;
    if (!decode_insn(&jmp, ea))
        return false;

    constexpr std::array jmp_types = {NN_jmp, NN_jmpfi, NN_jmpni};
    const bool is_jmp = std::any_of(jmp_types.begin(), jmp_types.end(),
                                    [&jmp](const int type) { return std::cmp_equal(jmp.itype, type); });
    if (!is_jmp)
        return false;

    const ea_t img_min = inf_get_min_ea();
    const ea_t img_max = inf_get_max_ea();

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

bool emulator::handle_call(uc_engine* uc, const uint64_t address, const uint32_t size, const insn_t& insn)
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

void emulator::hook_code(uc_engine* uc, const uint64_t address, const uint32_t size, void* user_data)
{
    emulator* current = reinterpret_cast<emulator*>(user_data);

    insn_t insn;
    if (!decode_insn(&insn, address))
        return;

    current->print_disasm(address);

    ++counters::instructions_executed;

    if (current->should_update_dialog)
        replace_wait_box("Emulating at 0x%a, executed %zu instructions", address,
                         counters::instructions_executed.load());

    if (instruction_classifier::should_skip(insn.itype))
    {
        const uint64_t rip = address + size;
        uc_reg_write(uc, UC_X86_REG_RIP, &rip);
        ++counters::skipped;
        return;
    }

    if (instruction_classifier::should_dump(insn.itype))
        current->dump_stack_strings();

    if (instruction_classifier::should_handle(insn.itype))
    {
        handler::handle(uc, address, insn.size, insn);
        return;
    }

    if (current->handle_call(uc, address, size, insn))
        return;

    if (!instruction_classifier::is_conditional(insn.itype))
        return;

    const uint64_t taken = insn.Op1.addr;
    const uint64_t fallthrough = address + size;

    if (!current->branches_.is_visited(fallthrough))
    {
        current->branches_.save_branch(uc, fallthrough);
        ++counters::branched;
    }
    else
    {
        ++counters::already_visited;
    }

    current->branches_.mark_visited(fallthrough);

    if (taken > address)
        current->force_branch(uc, insn);
}

bool emulator::hook_mem(uc_engine* uc, uc_mem_type type, const uint64_t address, int size, int64_t value,
                        void* user_data)
{
    constexpr uint64_t page_mask = ~0xFFFULL;
    const uint64_t page = address & page_mask;

    if (uc_mem_map(uc, page, 0x1000, UC_PROT_ALL) != UC_ERR_OK)
        return false;

    uint64_t rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);

    logger::debug("mapped missing page {0:x} for {1:x}, resuming...", page, rip);
    return true;
}

void emulator::reset()
{
    branches_.clear();
    string_list_.clear();

    counters::start_time.store(std::nullopt);
    counters::instructions_executed = 0;
    counters::branched = 0;
    counters::already_visited = 0;
    counters::skipped = 0;
    counters::external_calls = 0;
    counters::import_thunks = 0;

    should_update_dialog = true;
}

emulator::emulator()
{
    logger::debug("initializing...");
    reset();

    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &engine);
    if (err != UC_ERR_OK)
    {
        logger::info("failed to initialize engine: {0}", uc_strerror(err));
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
        logger::info("failed to map memory range {0:x} to {1:x}: {2}", img_min, img_max, uc_strerror(err));
        uc_close(engine);
        return;
    }

    const size_t size = img_max - img_min;
    std::vector<uint8_t> buffer(size);
    const ssize_t got = get_bytes(buffer.data(), size, img_min, GMB_READALL);
    if (got <= 0)
    {
        logger::info("failed to read memory from {0:x} to {1:x}: {2}", img_min, img_max, got);
        uc_close(engine);
        return;
    }

    err = uc_mem_write(engine, img_min, buffer.data(), size);
    if (err != UC_ERR_OK)
    {
        logger::info("failed to write memory from {0:x} with size {1:x}: {2}", img_min, size, uc_strerror(err));
        uc_close(engine);
        return;
    }

    err = uc_mem_map(engine, stack_base - stack_size, stack_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK)
    {
        logger::info("failed to map stack: {0}", uc_strerror(err));
        uc_close(engine);
        return;
    }

    uc_hook_add(engine, &code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(hook_code), this, 1, 0);
    uc_hook_add(engine, &mem_hook, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, reinterpret_cast<void*>(hook_mem), this, 1, 0);
}

emulator::~emulator()
{
    uc_close(engine);
}

const std::unordered_set<found_string_t, found_string_hash>& emulator::get_string_list() const noexcept
{
    return string_list_;
}

void emulator::run(ea_t start, const uint64_t max_time_ms, const uint64_t max_instr_branch)
{
    logger::debug("starting emulation from {0:x}...", start);

    if (!counters::start_time.load().has_value())
        counters::start_time.store(std::chrono::high_resolution_clock::now());

    overwrite_all_registers(0x2000);

    uc_reg_write(engine, UC_X86_REG_RSP, &stack_base);

    uint64_t entry = start;

    for (;;)
    {
        uc_reg_write(engine, UC_X86_REG_RIP, &entry);

        const uc_err err = uc_emu_start(engine, entry, 0, max_time_ms * 1000, max_instr_branch);
        if (err != UC_ERR_OK)
            logger::debug("emulation failure: {0}", uc_strerror(err));

        if (!branches_.has_pending())
            break;

        const auto state = branches_.take_next();
        uc_context_restore(engine, state.ctx);
        entry = state.pc;
    }
}