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
};

static std::optional<emulation_config> get_user_config()
{
    static constexpr const char form[] = "unxorer\n"
                                         "Start from:\n"
                                         "<#Current function:R>\n"
                                         "<#Every function (very slow!):R>\n"
                                         "<#Current cursor location:R>\n"
                                         "<#Entry point:R>>\n"
                                         "\n"
                                         "Limits (per branch):\n"
                                         "<Max time (ms):\t      D:20:10::>\n"
                                         "<Max instructions:\t   D:20:10::>\n";

    int scope_val = 0;
    uval_t max_time = 10000;
    uval_t max_instr = 100000;

    if (!ask_form(form, &scope_val, &max_time, &max_instr))
        return std::nullopt;

    return emulation_config{static_cast<emulation_scope>(scope_val), max_time, max_instr};
}

static void run_on_function(emulator& emu, ea_t start, uval_t max_time, uval_t max_instr)
{
    emu.run(start, max_time, max_instr);
    results::display(emu.get_string_list());
}

static void run_on_all_functions(emulator& emu, uval_t max_time, uval_t max_instr)
{
    const size_t total = get_func_qty();
    if (total == 0)
    {
        warning("No functions in the database");
        return;
    }

    logger::info("running on {0} functions in database", total);
    emu.should_update_dialog = false;

    for (size_t i = 0; i < total; i++)
    {
        const ea_t start = getn_func(i)->start_ea;
        replace_wait_box("Emulating function %zu/%zu at 0x%llx", i + 1, total, start);

        emu.run(start, max_time, max_instr);

        if (user_cancelled())
            break;
    }

    results::display(emu.get_string_list());
}

static plugmod_t* idaapi init()
{
#ifndef NDEBUG
    console::init();
#endif
    logger::title();
    return PLUGIN_OK;
}

static void idaapi term()
{
    /**/
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

    show_wait_box("Initializing");
    emulator emu;

    switch (config->scope)
    {
    case emulation_scope::current_function:
        if (const func_t* func = get_func(get_screen_ea()); func)
            run_on_function(emu, func->start_ea, config->max_time_ms, config->max_instructions);
        else
            warning("No function under cursor");
        break;

    case emulation_scope::every_function:
        run_on_all_functions(emu, config->max_time_ms, config->max_instructions);
        break;

    case emulation_scope::current_cursor:
        run_on_function(emu, get_screen_ea(), config->max_time_ms, config->max_instructions);
        break;

    case emulation_scope::entry_point:
        run_on_function(emu, inf_get_start_ea(), config->max_time_ms, config->max_instructions);
        break;
    }

    hide_wait_box();
    return true;
}

plugin_t PLUGIN = {IDP_INTERFACE_VERSION, 0, init, term, run, "", "", "unxorer", ""};