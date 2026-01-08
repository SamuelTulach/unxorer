#pragma once

constexpr ea_t stack_base = 0x00007FFF0000ULL;
constexpr size_t stack_size = 0x100000;

namespace counters
{
    // atomic for future multi-threading support
    inline std::atomic<size_t> instructions_executed = 0;
    inline std::atomic<size_t> branched = 0;
    inline std::atomic<size_t> already_visited = 0;
    inline std::atomic<size_t> skipped = 0;
    inline std::atomic<size_t> external_calls = 0;
    inline std::atomic<size_t> import_thunks = 0;
    inline std::atomic<std::optional<std::chrono::high_resolution_clock::time_point>> start_time;
}

class emulator
{
  private:
    uc_engine* engine = nullptr;
    uc_hook code_hook = 0;
    uc_hook mem_hook = 0;

    branch_manager branches_;
    std::unordered_set<found_string_t, found_string_hash> string_list_;
    std::unordered_map<uint64_t, size_t> loop_iterations_;
    size_t loop_iteration_limit = 0;
    std::chrono::high_resolution_clock::time_point next_waitbox_update;

    void overwrite_all_registers(uint64_t value) const;
    void print_disasm(ea_t address) const;
    void push_string(uint64_t rip, uint64_t rsp, std::string str);
    void dump_stack_strings();
    void force_branch(uc_engine* uc, const insn_t& insn) const;
    [[nodiscard]] bool is_external_thunk(ea_t ea) const;
    bool handle_call(uc_engine* uc, uint64_t address, uint32_t size, const insn_t& insn);

    static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    static bool hook_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

    void reset();

  public:
    bool should_update_dialog = true;

    [[nodiscard]] const std::unordered_set<found_string_t, found_string_hash>& get_string_list() const noexcept;
    emulator();
    ~emulator();
    void run(ea_t start, uint64_t max_time_ms, uint64_t max_instr, uint64_t max_loop_iterations);
};