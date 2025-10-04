#pragma once

class branch_manager
{
  public:
    struct branch_state_t
    {
        uc_context* ctx = nullptr;
        uint64_t pc = 0;

        branch_state_t() = default;
        branch_state_t(const branch_state_t&) = delete;
        branch_state_t& operator=(const branch_state_t&) = delete;

        branch_state_t(branch_state_t&& other) noexcept : ctx(other.ctx), pc(other.pc)
        {
            other.ctx = nullptr;
        }

        branch_state_t& operator=(branch_state_t&& other) noexcept
        {
            if (this == &other)
            {
                if (ctx)
                    uc_context_free(ctx);

                ctx = other.ctx;
                pc = other.pc;
                other.ctx = nullptr;
            }

            return *this;
        }

        ~branch_state_t()
        {
            if (ctx)
                uc_context_free(ctx);
        }
    };

    void save_branch(uc_engine* uc, uint64_t pc)
    {
        branch_state_t state;
        uc_context_alloc(uc, &state.ctx);
        uc_context_save(uc, state.ctx);
        state.pc = pc;
        pending_.push_back(std::move(state));
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

    [[nodiscard]] bool is_visited(uint64_t address) const noexcept
    {
        return visited_.contains(address);
    }

    void mark_visited(uint64_t address)
    {
        visited_.insert(address);
    }

    void clear()
    {
        pending_.clear();
        visited_.clear();
    }

  private:
    std::vector<branch_state_t> pending_;
    std::unordered_set<uint64_t> visited_;
};
