#include "global.hpp"

enum class emulation_scope
{
    current_function,
    every_function,
    current_cursor,
    entry_point
};

struct emulation_config
{
    emulation_scope scope;
    uval_t max_time_ms;
    uval_t max_instructions;
    uval_t max_loop_iterations;
};

static bool initialize_emulator(emulator& emu, bool update_dialog)
{
    if (!emu.is_ready())
    {
        warning("Failed to initialize emulator");
        return false;
    }

    emu.should_update_dialog = update_dialog;
    return true;
}

static std::optional<emulation_config> get_user_config()
{
    static constexpr const char form[] = "unxorer\n"
                                         "Start from:\n"
                                         "<#Current function:R>\n"
                                         "<#Every function (very slow!):R>\n"
                                         "<#Current cursor location:R>\n"
                                         "<#Entry point                                          :R>>\n"
                                         "\n"
                                         "Limits:\n"
                                         "<Max time (ms)                      : D:20:10::>\n"
                                         "<Max instructions (per function)    : D:20:10::>\n"
                                         "<Max loop iterations (per function) : D:20:10::>\n";

    int scope_val = 0;
    uval_t max_time = 60000;
    uval_t max_instr = 1000000;
    uval_t max_loops = 50;

    if (!ask_form(form, &scope_val, &max_time, &max_instr, &max_loops))
        return std::nullopt;

    return emulation_config{static_cast<emulation_scope>(scope_val), max_time, max_instr, max_loops};
}

static std::optional<ea_t> resolve_single_start(emulation_scope scope)
{
    switch (scope)
    {
    case emulation_scope::current_function:
        if (const func_t* func = get_func(get_screen_ea()); func != nullptr)
            return func->start_ea;

        warning("No function under cursor");
        return std::nullopt;

    case emulation_scope::current_cursor:
        return get_screen_ea();

    case emulation_scope::entry_point:
        return inf_get_start_ea();

    case emulation_scope::every_function:
        break;
    }

    return std::nullopt;
}

static void run_on_function(ea_t start, const emulation_config& config)
{
    emulator emu;
    if (!initialize_emulator(emu, true))
        return;

    emu.run(start, config.max_time_ms, config.max_instructions, config.max_loop_iterations);
    results::display(emu.get_string_list());
}

static std::vector<ea_t> collect_function_starts()
{
    std::vector<ea_t> starts;
    const size_t total = get_func_qty();
    starts.reserve(total);

    for (size_t i = 0; i < total; ++i)
    {
        if (const func_t* func = getn_func(i); func != nullptr)
            starts.push_back(func->start_ea);
    }

    return starts;
}

static void run_on_all_functions(const emulation_config& config)
{
    const std::vector<ea_t> starts = collect_function_starts();
    if (starts.empty())
    {
        warning("No functions in the database");
        return;
    }

    emulator emu;
    if (!initialize_emulator(emu, false))
        return;

    const size_t total = starts.size();
    logger::info("running on {0} functions in database", total);

    std::unordered_set<found_string_t, found_string_hash> aggregated;
    aggregated.reserve(total);

    for (size_t i = 0; i < total; ++i)
    {
        const ea_t start = starts[i];
        replace_wait_box("Emulating function %zu/%zu at 0x%llx", i + 1, total, start);
        emu.run(start, config.max_time_ms, config.max_instructions, config.max_loop_iterations);

        const auto& found = emu.get_string_list();
        aggregated.insert(found.begin(), found.end());

        if (user_cancelled())
            break;
    }

    results::display(aggregated);
}

static plugmod_t* idaapi init()
{
#ifndef NDEBUG
    console::init();
#endif
    logger::title();
    return PLUGIN_OK;
}

static bool idaapi run(size_t)
{
    if (PH.id != PLFM_386 || !inf_is_64bit())
    {
        warning("CPU is not x86_64");
        return false;
    }

    const auto config = get_user_config();
    if (!config)
        return false;

    counters::reset();
    show_wait_box("Initializing");

    if (config->scope == emulation_scope::every_function)
    {
        run_on_all_functions(*config);
    }
    else if (const auto start = resolve_single_start(config->scope); start.has_value())
    {
        run_on_function(*start, *config);
    }

    hide_wait_box();
    return true;
}

plugin_t PLUGIN = {IDP_INTERFACE_VERSION, 0, init, nullptr, run, "", "", "unxorer", ""};
