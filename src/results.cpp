#include "global.hpp"

class results_chooser_t : public chooser_t
{
  protected:
    static const int results_widths_[];
    static const char* const results_headers_[];

  private:
    std::unordered_set<emulator::found_string_t, emulator::found_string_hash> list_;

  public:
    results_chooser_t(const char* desired_title,
                      const std::unordered_set<emulator::found_string_t, emulator::found_string_hash>& list)
        : chooser_t(0, 3, results_widths_, results_headers_, desired_title)
    {
        list_ = list;
    }

    virtual const void* get_obj_id(size_t* len) const
    {
        *len = strlen(title);
        return title;
    }

    virtual size_t idaapi get_count() const
    {
        return list_.size();
    }

    virtual void idaapi get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const
    {
        if (n >= list_.size())
            return;

        const auto it = std::next(list_.begin(), n);
        const emulator::found_string_t& item = *it;

        (*cols)[0].sprnt("%016" PRIX64, item.rip);
        (*cols)[1].sprnt("%016" PRIX64, item.rsp);
        (*cols)[2].sprnt("%s", item.data.c_str());
    }

    virtual cbret_t idaapi enter(size_t n)
    {
        if (n >= list_.size())
            return false;

        const auto it = std::next(list_.begin(), n);
        jumpto(it->rip);

        return false;
    }
};

const int results_chooser_t::results_widths_[] = {16, 16, 32};
const char* const results_chooser_t::results_headers_[] = {"rip", "rsp", "string"};

void results::display(const std::unordered_set<emulator::found_string_t, emulator::found_string_hash>& string_list)
{
    const auto duration = std::chrono::high_resolution_clock::now() -
                          counters::start_time.load().value_or(std::chrono::high_resolution_clock::now());

    logger::print("stats:");
    logger::print(" - instructions:    {0}", counters::instructions_executed.load());
    logger::print(" - time:            {0}", strings::format_duration(duration));

    logger::print("finished, found {0} unique strings", string_list.size());

    const auto results = new results_chooser_t("unxorer", string_list);
    results->choose();
}