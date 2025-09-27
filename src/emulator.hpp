#pragma once

namespace emulator
{
    constexpr ea_t stack_base = 0x00007FFF0000ULL;
    constexpr size_t stack_size = 0x100000;

    inline uc_engine* engine = nullptr;
    inline uc_hook code_hook = 0;
    inline uc_hook mem_hook = 0;
    inline uc_hook fetch_hook = 0;

    inline bool should_update_dialog = true;

    struct branch_state_t
    {
        uc_context* ctx = nullptr;
        uint64_t pc = 0;

        branch_state_t() = default;
        branch_state_t(const branch_state_t&) = delete;
        branch_state_t& operator=(const branch_state_t&) = delete;

        branch_state_t(branch_state_t&& o) noexcept : ctx(o.ctx), pc(o.pc)
        {
            o.ctx = nullptr;
        }

        ~branch_state_t()
        {
            if (ctx)
                uc_context_free(ctx);
        }
    };

    inline std::vector<branch_state_t> pending;
    inline std::unordered_set<uint64_t> visited;

    namespace counters
    {
        inline size_t instructions_executed = 0;
        inline size_t branched = 0;
        inline size_t already_visited = 0;
        inline size_t skipped = 0;
        inline size_t external_calls = 0;
        inline size_t import_thunks = 0;
        inline std::optional<std::chrono::high_resolution_clock::time_point> start_time;
    }

    void overwrite_all_registers(uint64_t value);

    struct found_string_t
    {
        uint64_t rip = 0;
        uint64_t rsp = 0;
        std::string data = {};

        bool operator==(const found_string_t& other) const noexcept
        {
            return data == other.data;
        }
    };

    struct found_string_hash
    {
        size_t operator()(const found_string_t& input) const noexcept
        {
            return std::hash<std::string>{}(input.data);
        }
    };

    inline std::unordered_set<found_string_t, found_string_hash> string_list;
    void print_disasm(const ea_t& address);
    void push_string(const uint64_t rip, const uint64_t rsp, const std::string& str);
    void dump_stack_strings();

    bool is_conditional(const insn_t& insn);
    bool should_dump(const insn_t& insn);
    bool should_skip(const insn_t& insn);
    bool should_handle(const insn_t& insn);

    void force_branch(uc_engine* uc, const insn_t& insn);
    bool is_external_thunk(ea_t ea);
    bool handle_call(uc_engine* uc, uint64_t address, uint32_t size, insn_t insn);

    void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    bool hook_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

    void reset();
    uc_err safe_start(uc_engine* uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);
    void run(ea_t start, uint64_t max_time_ms, uint64_t max_instr_branch);
}