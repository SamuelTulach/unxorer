#include "global.hpp"

class results_chooser_t final : public chooser_t
{
  protected:
    static constexpr int results_widths_[] = {16, 16, 32};
    static constexpr const char* const results_headers_[] = {"rip", "ptr", "string"};

  private:
    std::vector<found_string_t> rows_;

  public:
    results_chooser_t(const char* desired_title, std::vector<found_string_t> list)
        : chooser_t(0, 3, results_widths_, results_headers_, desired_title), rows_(std::move(list))
    {
    }

    const void* get_obj_id(size_t* len) const override
    {
        *len = std::strlen(title);
        return title;
    }

    [[nodiscard]] size_t idaapi get_count() const override
    {
        return rows_.size();
    }

    void idaapi get_row(qstrvec_t* cols, int*, chooser_item_attrs_t*, size_t n) const override
    {
        if (n >= rows_.size())
            return;

        const auto& row = rows_[n];
        (*cols)[0].sprnt("%016" PRIX64, row.rip);
        (*cols)[1].sprnt("%016" PRIX64, row.ptr);
        (*cols)[2].sprnt("%s", row.data.c_str());
    }

    cbret_t idaapi enter(size_t n) override
    {
        if (n < rows_.size())
            jumpto(rows_[n].rip);

        return cbret_t(0);
    }
};

void results::display(const std::unordered_set<found_string_t, found_string_hash>& string_list)
{
    const auto now = std::chrono::high_resolution_clock::now();
    const auto start = counters::start_time.load().value_or(now);
    const auto duration = now - start;

    logger::info("stats:");

    const auto print_stat = [](std::string_view label, const auto& value) {
        logger::info(" - {0:<15}{1}", fmt::format("{}:", label), value);
    };

    print_stat("instructions", counters::instructions_executed.load());
    print_stat("branches", counters::branched.load());
    print_stat("visited", counters::already_visited.load());
    print_stat("skipped", counters::skipped.load());
    print_stat("external", counters::external_calls.load());
    print_stat("imports", counters::import_thunks.load());
    print_stat("time", strings::format_duration(duration));
    logger::info("finished, found {0} unique strings", string_list.size());

    std::vector<found_string_t> display_list(string_list.begin(), string_list.end());
    auto* chooser = new results_chooser_t("unxorer", std::move(display_list));
    chooser->choose();
}
