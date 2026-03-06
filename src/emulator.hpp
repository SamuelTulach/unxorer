#pragma once

constexpr ea_t stack_base = 0x00007FFF0000ULL;
constexpr size_t stack_size = 0x100000;

namespace counters
{
    inline std::atomic<size_t> instructions_executed = 0;
    inline std::atomic<size_t> branched = 0;
    inline std::atomic<size_t> already_visited = 0;
    inline std::atomic<size_t> skipped = 0;
    inline std::atomic<size_t> external_calls = 0;
    inline std::atomic<size_t> import_thunks = 0;
    inline std::atomic<std::optional<std::chrono::high_resolution_clock::time_point>> start_time;

    inline void reset()
    {
        instructions_executed = 0;
        branched = 0;
        already_visited = 0;
        skipped = 0;
        external_calls = 0;
        import_thunks = 0;
        start_time.store(std::nullopt);
    }
}

class emulator
{
  private:
    class branch_manager
    {
      public:
        struct branch_key
        {
            uint64_t rip;
            uint64_t target;

            bool operator==(const branch_key& other) const noexcept
            {
                return rip == other.rip && target == other.target;
            }
        };

        struct branch_key_hash
        {
            size_t operator()(const branch_key& key) const noexcept
            {
                const size_t h1 = std::hash<uint64_t>{}(key.rip);
                const size_t h2 = std::hash<uint64_t>{}(key.target);
                return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
            }
        };

        struct context_deleter
        {
            void operator()(uc_context* ctx) const noexcept
            {
                if (ctx != nullptr)
                    uc_context_free(ctx);
            }
        };

        using context_ptr = std::unique_ptr<uc_context, context_deleter>;

        struct branch_state_t
        {
            context_ptr ctx;
            uint64_t pc = 0;

            branch_state_t() = default;
            branch_state_t(context_ptr context, uint64_t entry_pc) : ctx(std::move(context)), pc(entry_pc)
            {
            }

            branch_state_t(const branch_state_t&) = delete;
            branch_state_t& operator=(const branch_state_t&) = delete;
            branch_state_t(branch_state_t&&) noexcept = default;
            branch_state_t& operator=(branch_state_t&&) noexcept = default;
        };

        bool save_branch(uc_engine* uc, uint64_t pc)
        {
            uc_context* raw_ctx = nullptr;
            if (uc_context_alloc(uc, &raw_ctx) != UC_ERR_OK)
                return false;

            context_ptr ctx(raw_ctx);
            if (uc_context_save(uc, ctx.get()) != UC_ERR_OK)
                return false;

            pending_.emplace_back(std::move(ctx), pc);
            return true;
        }

        [[nodiscard]] bool has_pending() const noexcept
        {
            return !pending_.empty();
        }

        branch_state_t take_next()
        {
            auto state = std::move(pending_.back());
            pending_.pop_back();
            return state;
        }

        [[nodiscard]] bool is_visited(const branch_key& key) const noexcept
        {
            return visited_.contains(key);
        }

        void mark_visited(const branch_key& key)
        {
            visited_.insert(key);
        }

        void clear()
        {
            pending_.clear();
            visited_.clear();
        }

      private:
        std::vector<branch_state_t> pending_;
        std::unordered_set<branch_key, branch_key_hash> visited_;
    };

    struct loop_state
    {
        uint64_t hits = 0;
        uint64_t last_target = 0;
    };

    uc_engine* engine = nullptr;
    uc_hook code_hook = 0;
    uc_hook mem_hook = 0;

    ea_t image_min_ = BADADDR;
    ea_t image_max_ = BADADDR;
    branch_manager branches_;
    std::unordered_set<found_string_t, found_string_hash> string_list_;
    std::unordered_map<uint64_t, loop_state> loop_iterations_;
    size_t loop_iteration_limit = 0;
    std::chrono::high_resolution_clock::time_point next_waitbox_update = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> stack_buffer_;
    std::vector<uint8_t> image_buffer_;
    std::vector<uint8_t> image_backup_;

    void overwrite_all_registers(uint64_t value) const;
    void print_disasm(ea_t address) const;
    void push_string(uint64_t rip, uint64_t rsp, std::string str);
    void dump_stack_strings();
    void force_branch(uc_engine* uc, const insn_t& insn) const;
    [[nodiscard]] bool is_external_thunk(ea_t ea) const;
    bool handle_call(uc_engine* uc, uint64_t address, uint32_t size, const insn_t& insn);
    bool schedule_branch(uc_engine* uc, uint64_t from, uint64_t target);
    void discover_indirect_targets(uc_engine* uc, uint64_t address, const insn_t& insn);

    static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
    static bool hook_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

  public:
    bool should_update_dialog = true;

    [[nodiscard]] const std::unordered_set<found_string_t, found_string_hash>& get_string_list() const noexcept;
    emulator();
    ~emulator();
    [[nodiscard]] bool is_ready() const noexcept
    {
        return engine != nullptr;
    }
    void run(ea_t start, uint64_t max_time_ms, uint64_t max_instr, uint64_t max_loop_iterations);
};
