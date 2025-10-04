#include "global.hpp"

class results_chooser_t final : public chooser_t
{
  protected:
    static constexpr int results_widths_[] = {16, 16, 32};
    static constexpr const char* const results_headers_[] = {"rip", "rsp", "string"};

  private:
    std::vector<found_string_t> list_;

  public:
    results_chooser_t(const char* desired_title, const std::unordered_set<found_string_t, found_string_hash>& list)
        : chooser_t(0, 3, results_widths_, results_headers_, desired_title)
    {
        list_.reserve(list.size());
        list_.assign(list.begin(), list.end());
    }

    const void* get_obj_id(size_t* len) const override
    {
        *len = strlen(title);
        return title;
    }

    [[nodiscard]] size_t idaapi get_count() const override
    {
        return list_.size();
    }

    void idaapi get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const override
    {
        if (n >= list_.size())
            return;

        const auto& item = list_[n];
        (*cols)[0].sprnt("%016" PRIX64, item.rip);
        (*cols)[1].sprnt("%016" PRIX64, item.rsp);
        (*cols)[2].sprnt("%s", item.data.c_str());
    }

    cbret_t idaapi enter(size_t n) override
    {
        if (n < list_.size())
            jumpto(list_[n].rip);

        return cbret_t(0);
    }
};

void results::display(const std::unordered_set<found_string_t, found_string_hash>& string_list)
{
    const auto duration = std::chrono::high_resolution_clock::now() -
                          counters::start_time.load().value_or(std::chrono::high_resolution_clock::now());

    logger::info("stats:");
    logger::info(" - instructions:    {0}", counters::instructions_executed.load());
    logger::info(" - time:            {0}", strings::format_duration(duration));
    logger::info("finished, found {0} unique strings", string_list.size());

    const auto results = new results_chooser_t("unxorer", string_list);
    results->choose();
}