#include "global.hpp"

namespace
{
    constexpr auto call_types = std::to_array<int>({NN_call, NN_callfi, NN_callni});
    constexpr auto jump_types = std::to_array<int>({NN_jmp, NN_jmpfi, NN_jmpni});
    constexpr auto indirect_control_types =
        std::to_array<int>({NN_jmp, NN_jmpfi, NN_jmpni, NN_call, NN_callfi, NN_callni});

    constexpr uint64_t flag_cf = 0x00000001ull;
    constexpr uint64_t flag_pf = 0x00000004ull;
    constexpr uint64_t flag_zf = 0x00000040ull;
    constexpr uint64_t flag_sf = 0x00000080ull;
    constexpr uint64_t flag_of = 0x00000800ull;

    bool is_inside_image(uint64_t address, ea_t image_min, ea_t image_max)
    {
        return address >= image_min && address < image_max;
    }

    bool resolve_operand_target(uc_engine* uc, const op_t& op, uint64_t& target)
    {
        switch (op.type)
        {
        case o_near:
        case o_far:
            target = op.addr;
            return true;

        case o_mem:
            return uc_mem_read(uc, op.addr, &target, sizeof(target)) == UC_ERR_OK;

        case o_displ: {
            const uint64_t mem_addr = vector_operations::calculate_effective_address(uc, op);
            return uc_mem_read(uc, mem_addr, &target, sizeof(target)) == UC_ERR_OK;
        }

        default:
            return false;
        }
    }

    uint16_t read_u16le(const uint8_t* data)
    {
        return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
    }
}

void emulator::overwrite_all_registers(const uint64_t value) const
{
    constexpr auto registers = std::to_array<int>({UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                                                   UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
                                                   UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
                                                   UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15});

    for (const int reg : registers)
    {
        if (uc_reg_write(engine, reg, &value) != UC_ERR_OK)
        {
            if (allow_ui_calls)
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

    str = strings::escape_control_chars(str);
    strings::trim(str);
    if (str.empty())
        return;

    const size_t hash = strings::hash_string(str);
    string_list_.emplace(found_string_t{rip, rsp, hash, std::move(str)});
}

void emulator::dump_stack_strings()
{
    uint64_t rsp = 0;
    uc_reg_read(engine, UC_X86_REG_RSP, &rsp);

    uint64_t rip = 0;
    uc_reg_read(engine, UC_X86_REG_RIP, &rip);

    if (rsp < stack_base - stack_size || rsp >= stack_base)
    {
        if (allow_ui_calls)
            logger::debug("rsp {0:x} is out of stack bounds ({1:x} - {2:x})", rsp, stack_base - stack_size, stack_base);
        return;
    }

    constexpr size_t max_scan = 0x8000;
    const size_t scan_size = std::min(static_cast<size_t>(stack_base - rsp), max_scan);

    const uint64_t stack_begin = stack_base - stack_size;
    const size_t offset = static_cast<size_t>(rsp - stack_begin);
    const uint8_t* buffer = stack_buffer_.data() + offset;

    for (size_t i = 0; i < scan_size;)
    {
        if (strings::is_ascii_printable(buffer[i]))
        {
            size_t end = i;
            while (end < scan_size && strings::is_ascii_printable(buffer[end]))
                ++end;

            if (end - i >= 4 && end < scan_size && buffer[end] == 0)
            {
                std::string candidate(reinterpret_cast<const char*>(buffer + i), end - i);
                push_string(rip, rsp + i, std::move(candidate));
            }

            i = end + 1;
            continue;
        }

        if (i + 1 < scan_size && strings::is_utf16_printable(read_u16le(buffer + i)))
        {
            size_t end = i;
            while (end + 1 < scan_size && strings::is_utf16_printable(read_u16le(buffer + end)))
                end += 2;

            if ((end - i) / 2 >= 4 && end + 1 < scan_size && buffer[end] == 0 && buffer[end + 1] == 0)
            {
                std::string candidate = strings::utf16le_to_ascii(buffer + i, (end - i) / 2);
                push_string(rip, rsp + i, std::move(candidate));
            }

            i = end + 2;
            continue;
        }

        ++i;
    }
}

bool emulator::schedule_branch(uc_engine* uc, const uint64_t from, const uint64_t target)
{
    branch_manager::branch_key key{from, target};
    if (branches_.is_visited(key))
    {
        ++counters::already_visited;
        return false;
    }

    if (!is_inside_image(target, image_min_, image_max_))
    {
        branches_.mark_visited(key);
        return false;
    }

    if (!branches_.save_branch(uc, target))
    {
        branches_.mark_visited(key);
        if (allow_ui_calls)
            logger::debug("failed to snapshot branch at {0:x}", target);
        return false;
    }

    branches_.mark_visited(key);
    ++counters::branched;
    return true;
}

void emulator::discover_indirect_targets(uc_engine* uc, const uint64_t address, const insn_t& insn)
{
    if (!instruction_classifier::contains(indirect_control_types, insn.itype))
        return;

    if (insn.Op1.type != o_mem && insn.Op1.type != o_displ)
        return;

    uint64_t target = 0;
    if (resolve_operand_target(uc, insn.Op1, target))
        schedule_branch(uc, address, target);
}

void emulator::force_branch(uc_engine* uc, const insn_t& insn) const
{
    uint64_t eflags = 0;
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);

    auto set = [&](const uint64_t mask) { eflags |= mask; };
    auto clear = [&](const uint64_t mask) { eflags &= ~mask; };

    switch (insn.itype)
    {
    case NN_jz:
    case NN_je:
    case NN_cmovz:
    case NN_sete:
    case NN_setz:
        set(flag_zf);
        break;
    case NN_jnz:
    case NN_jne:
    case NN_cmovnz:
    case NN_setne:
    case NN_setnz:
        clear(flag_zf);
        break;

    case NN_jc:
    case NN_jb:
    case NN_jnae:
    case NN_cmovb:
    case NN_setb:
    case NN_setc:
        set(flag_cf);
        break;
    case NN_jnc:
    case NN_jnb:
    case NN_jae:
    case NN_setae:
        clear(flag_cf);
        break;

    case NN_js:
    case NN_cmovs:
    case NN_sets:
        set(flag_sf);
        break;
    case NN_jns:
    case NN_cmovns:
    case NN_setns:
        clear(flag_sf);
        break;

    case NN_jo:
    case NN_cmovo:
    case NN_seto:
        set(flag_of);
        break;
    case NN_jno:
    case NN_cmovno:
    case NN_setno:
        clear(flag_of);
        break;

    case NN_jp:
    case NN_jpe:
    case NN_cmovp:
    case NN_setp:
        set(flag_pf);
        break;
    case NN_jnp:
    case NN_jpo:
    case NN_cmovnp:
    case NN_setnp:
    case NN_setpo:
        clear(flag_pf);
        break;

    case NN_ja:
    case NN_jnbe:
    case NN_cmova:
    case NN_seta:
        clear(flag_cf | flag_zf);
        break;
    case NN_jbe:
    case NN_jna:
    case NN_cmovbe:
    case NN_setbe:
        set(flag_cf);
        break;

    case NN_jg:
    case NN_jnle:
    case NN_cmovg:
    case NN_setg:
        clear(flag_zf | flag_sf | flag_of);
        break;
    case NN_jge:
    case NN_jnl:
    case NN_cmovge:
    case NN_setge:
        clear(flag_sf | flag_of);
        break;
    case NN_jl:
    case NN_jnge:
    case NN_cmovl:
    case NN_setl:
        set(flag_sf);
        clear(flag_of);
        break;
    case NN_jle:
    case NN_jng:
    case NN_cmovle:
    case NN_setle:
        set(flag_zf);
        break;

    case NN_jcxz:
    case NN_jecxz:
    case NN_jrcxz: {
        constexpr uint64_t rcx = 0;
        uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    }
    break;

    default:
        break;
    }

    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);
}

bool emulator::is_external_thunk(const ea_t address) const
{
    insn_t jump;
    if (!try_get_insn(address, jump) || !instruction_classifier::contains(jump_types, jump.itype))
        return false;

    uint64_t target = 0;
    if (!resolve_operand_target(engine, jump.Op1, target))
        return false;

    return !is_inside_image(target, image_min_, image_max_);
}

bool emulator::handle_call(uc_engine* uc, const uint64_t address, const uint32_t size, const insn_t& insn)
{
    if (!instruction_classifier::contains(call_types, insn.itype))
        return false;

    uint64_t target = 0;
    const bool has_target = resolve_operand_target(uc, insn.Op1, target);
    bool external = has_target && !is_inside_image(target, image_min_, image_max_);

    if (!external && has_target && is_external_thunk(target))
    {
        ++counters::import_thunks;
        external = true;
    }

    if (!external)
        return false;

    const uint64_t return_address = address + size;
    uc_reg_write(uc, UC_X86_REG_RIP, &return_address);

    constexpr uint64_t return_value = 0;
    uc_reg_write(uc, UC_X86_REG_RAX, &return_value);

    ++counters::external_calls;
    return true;
}

void emulator::hook_code(uc_engine* uc, const uint64_t address, const uint32_t size, void* user_data)
{
    emulator* current = reinterpret_cast<emulator*>(user_data);

    if (current->stop_requested_ != nullptr && current->stop_requested_->load(std::memory_order_relaxed))
    {
        uc_emu_stop(uc);
        return;
    }

    insn_t insn;
    if (!current->try_get_insn(address, insn))
        return;

#ifndef NDEBUG
    if (current->allow_ui_calls)
        current->print_disasm(address);
#endif

    ++counters::instructions_executed;

    if (current->should_update_dialog)
    {
        const auto now = std::chrono::high_resolution_clock::now();
        if (now >= current->next_waitbox_update)
        {
            const size_t executed = counters::instructions_executed.load();
            replace_wait_box("Emulating at 0x%a, executed %zu instructions", address, executed);
            current->next_waitbox_update = now + std::chrono::seconds(1);
        }
    }

    if (instruction_classifier::should_skip(insn.itype))
    {
        const uint64_t next = address + size;
        uc_reg_write(uc, UC_X86_REG_RIP, &next);
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

    current->discover_indirect_targets(uc, address, insn);

    if (!instruction_classifier::is_conditional(insn.itype))
        return;

    if (!instruction_classifier::is_branch(insn.itype))
    {
        current->force_branch(uc, insn);
        return;
    }

    const uint64_t taken = insn.Op1.addr;
    const uint64_t fallthrough = address + size;
    current->schedule_branch(uc, address, fallthrough);

    if (taken <= address)
    {
        if (current->loop_iteration_limit == 0)
        {
            current->loop_iterations_.erase(address);
        }
        else
        {
            auto entry = current->loop_iterations_.try_emplace(address, emulator::loop_state{0, taken}).first;
            auto& state = entry->second;
            if (state.last_target != taken)
            {
                state.last_target = taken;
                state.hits = 0;
            }

            ++state.hits;
            const uint64_t span = address - taken;
            uint64_t allowance = current->loop_iteration_limit;
            const uint64_t bonus = span / 4;
            if (bonus > std::numeric_limits<uint64_t>::max() - allowance)
                allowance = std::numeric_limits<uint64_t>::max();
            else
                allowance += bonus;

            if (state.hits >= allowance)
            {
                current->loop_iterations_.erase(entry);
                uc_reg_write(uc, UC_X86_REG_RIP, &fallthrough);
                return;
            }
        }
    }
    else
    {
        current->loop_iterations_.erase(address);
    }

    if (taken > address)
        current->force_branch(uc, insn);
}

bool emulator::hook_mem(uc_engine* uc, uc_mem_type, const uint64_t address, int, int64_t, void* user_data)
{
    emulator* current = reinterpret_cast<emulator*>(user_data);

    uint64_t rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);

    size_t advance = 1;
    insn_t insn;
    if (current->try_get_insn(rip, insn) && insn.size > 0)
        advance = insn.size;

    const uint64_t next = rip + advance;
    uc_reg_write(uc, UC_X86_REG_RIP, &next);

    if (current->allow_ui_calls)
        logger::debug("skipped instruction {0:x} due to unmapped access at {1:x}", rip, address);

    return true;
}

bool emulator::try_get_insn(const uint64_t address, insn_t& insn) const
{
    const auto it = instruction_snapshot_.decoded.find(address);
    if (it == instruction_snapshot_.decoded.end())
        return false;

    insn = it->second;
    return true;
}

emulator::emulator(const image_snapshot_t& image_snapshot, const instruction_snapshot_t& instruction_snapshot,
                   const bool allow_ui)
    : instruction_snapshot_(instruction_snapshot)
{
    allow_ui_calls = allow_ui;
    stack_buffer_.resize(stack_size);

    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &engine);
    if (err != UC_ERR_OK)
    {
        if (allow_ui_calls)
            logger::info("failed to initialize engine: {0}", uc_strerror(err));
        engine = nullptr;
        return;
    }

    auto cleanup = [&]() {
        if (engine != nullptr)
        {
            uc_close(engine);
            engine = nullptr;
        }
    };

    image_min_ = image_snapshot.image_min;
    image_max_ = image_snapshot.image_max;
    image_map_start_ = image_snapshot.map_start;
    image_map_size_ = image_snapshot.map_size;
    image_backup_ = image_snapshot.image_backup;
    image_buffer_ = image_backup_;

    if (image_min_ == BADADDR || image_max_ == BADADDR || image_map_size_ == 0 || image_backup_.empty())
    {
        if (allow_ui_calls)
            logger::info("invalid image snapshot");
        cleanup();
        return;
    }

    const size_t image_size = static_cast<size_t>(image_max_ - image_min_);
    const size_t image_offset = static_cast<size_t>(image_min_ - image_map_start_);
    const size_t required = image_offset + image_size;
    if (required > image_buffer_.size())
    {
        if (allow_ui_calls)
            logger::info("image snapshot size mismatch");
        cleanup();
        return;
    }

    err = uc_mem_map_ptr(engine, image_map_start_, image_map_size_, UC_PROT_ALL, image_buffer_.data());
    if (err != UC_ERR_OK)
    {
        if (allow_ui_calls)
            logger::info("failed to map image memory range {0:x} to {1:x}: {2}", image_min_, image_max_,
                         uc_strerror(err));
        cleanup();
        return;
    }

    err =
        uc_mem_map_ptr(engine, stack_base - stack_size, stack_size, UC_PROT_READ | UC_PROT_WRITE, stack_buffer_.data());
    if (err != UC_ERR_OK)
    {
        if (allow_ui_calls)
            logger::info("failed to map stack: {0}", uc_strerror(err));
        cleanup();
        return;
    }

    err = uc_hook_add(engine, &code_hook, UC_HOOK_CODE, reinterpret_cast<void*>(hook_code), this, 1, 0);
    if (err != UC_ERR_OK)
    {
        if (allow_ui_calls)
            logger::info("failed to install code hook: {0}", uc_strerror(err));
        cleanup();
        return;
    }

    err = uc_hook_add(engine, &mem_hook, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                      reinterpret_cast<void*>(hook_mem), this, 1, 0);
    if (err != UC_ERR_OK)
    {
        if (allow_ui_calls)
            logger::info("failed to install memory hook: {0}", uc_strerror(err));
        cleanup();
        return;
    }
}

emulator::~emulator()
{
    if (engine != nullptr)
    {
        uc_close(engine);
        engine = nullptr;
    }
}

const std::unordered_set<found_string_t, found_string_hash>& emulator::get_string_list() const noexcept
{
    return string_list_;
}

void emulator::run(ea_t start, const uint64_t max_time_ms, const uint64_t max_instr, const uint64_t max_loop_iterations,
                   const std::atomic_bool* stop_requested)
{
    if (engine == nullptr)
        return;

    stop_requested_ = stop_requested;

    if (allow_ui_calls)
        logger::debug("starting emulation from {0:x}...", start);

    branches_.clear();
    string_list_.clear();
    loop_iterations_.clear();
    loop_iteration_limit = max_loop_iterations;
    next_waitbox_update = std::chrono::high_resolution_clock::now();

    std::copy(image_backup_.begin(), image_backup_.end(), image_buffer_.begin());
    std::fill(stack_buffer_.begin(), stack_buffer_.end(), 0);

    if (!counters::start_time.load().has_value())
        counters::start_time.store(std::chrono::high_resolution_clock::now());

    overwrite_all_registers(0x2000);

    const uint64_t initial_rsp = stack_base - 0x1000;
    uc_reg_write(engine, UC_X86_REG_RSP, &initial_rsp);

    const bool limit_time = max_time_ms != 0;
    const bool limit_instr = max_instr != 0;
    uint64_t remaining_time_us = max_time_ms * 1000;
    uint64_t instructions_left = max_instr;

    uint64_t entry = start;
    for (;;)
    {
        if (stop_requested_ != nullptr && stop_requested_->load(std::memory_order_relaxed))
            break;

        if ((limit_time && remaining_time_us == 0) || (limit_instr && instructions_left == 0))
            break;

        uc_reg_write(engine, UC_X86_REG_RIP, &entry);

        const uint64_t instr_slice = limit_instr ? instructions_left : 0;
        const uint64_t time_slice = limit_time ? remaining_time_us : 0;
        const auto slice_begin = std::chrono::high_resolution_clock::now();
        const uint64_t instr_before = counters::instructions_executed.load();

        const uc_err err = uc_emu_start(engine, entry, 0, time_slice, instr_slice);
        if (err != UC_ERR_OK && allow_ui_calls)
            logger::debug("emulation failure: {0}", uc_strerror(err));

        if (limit_instr)
        {
            const uint64_t instr_after = counters::instructions_executed.load();
            const uint64_t delta = instr_after - instr_before;
            instructions_left = (delta >= instructions_left) ? 0 : instructions_left - delta;
        }

        if (limit_time)
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - slice_begin);
            const uint64_t elapsed_us = static_cast<uint64_t>(elapsed.count());
            remaining_time_us = (elapsed_us >= remaining_time_us) ? 0 : remaining_time_us - elapsed_us;
        }

        if (!branches_.has_pending())
            break;

        auto state = branches_.take_next();
        if (uc_context_restore(engine, state.ctx.get()) != UC_ERR_OK)
        {
            if (allow_ui_calls)
                logger::debug("failed to restore branch context");
            break;
        }

        entry = state.pc;
    }

    stop_requested_ = nullptr;
}

std::optional<emulator::image_snapshot_t> emulator::capture_image_snapshot()
{
    constexpr uint64_t page_size = 0x1000;
    constexpr uint64_t page_mask = ~(page_size - 1);

    const ea_t image_min = inf_get_min_ea();
    const ea_t image_max = inf_get_max_ea();
    if (image_min == BADADDR || image_max == BADADDR || image_max <= image_min)
        return std::nullopt;

    const uint64_t map_start = image_min & page_mask;
    const uint64_t map_end = (image_max + page_size - 1) & page_mask;
    const size_t map_size = static_cast<size_t>(map_end - map_start);
    const size_t image_size = static_cast<size_t>(image_max - image_min);
    const size_t image_offset = static_cast<size_t>(image_min - map_start);

    image_snapshot_t snapshot;
    snapshot.image_min = image_min;
    snapshot.image_max = image_max;
    snapshot.map_start = map_start;
    snapshot.map_size = map_size;
    snapshot.image_backup.assign(map_size, 0);

    const ssize_t got = get_bytes(snapshot.image_backup.data() + image_offset, image_size, image_min, GMB_READALL);
    if (got <= 0)
        return std::nullopt;

    return snapshot;
}

std::optional<emulator::instruction_snapshot_t> emulator::capture_instruction_snapshot(const ea_t image_min,
                                                                                       const ea_t image_max)
{
    if (image_min == BADADDR || image_max == BADADDR || image_max <= image_min)
        return std::nullopt;

    instruction_snapshot_t snapshot;
    const uint64_t image_size = image_max - image_min;
    snapshot.decoded.reserve(static_cast<size_t>(image_size / 4));

    for (ea_t ea = image_min; ea < image_max;)
    {
        insn_t insn;
        if (!decode_insn(&insn, ea) || insn.size == 0)
        {
            ++ea;
            continue;
        }

        snapshot.decoded.emplace(ea, insn);
        ea += insn.size;
    }

    return snapshot;
}
