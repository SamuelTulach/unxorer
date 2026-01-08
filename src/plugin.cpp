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

static void run_on_function(emulator& emu, ea_t start, uval_t max_time, uval_t max_instr, uval_t max_loops)
{
    emu.run(start, max_time, max_instr, max_loops);
    results::display(emu.get_string_list());
}

static void run_on_all_functions(emulator& emu, uval_t max_time, uval_t max_instr, uval_t max_loops)
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

        emu.run(start, max_time, max_instr, max_loops);

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
            run_on_function(emu, func->start_ea, config->max_time_ms, config->max_instructions,
                            config->max_loop_iterations);
        else
            warning("No function under cursor");
        break;

    case emulation_scope::every_function:
        run_on_all_functions(emu, config->max_time_ms, config->max_instructions, config->max_loop_iterations);
        break;

    case emulation_scope::current_cursor:
        run_on_function(emu, get_screen_ea(), config->max_time_ms, config->max_instructions,
                        config->max_loop_iterations);
        break;

    case emulation_scope::entry_point:
        run_on_function(emu, inf_get_start_ea(), config->max_time_ms, config->max_instructions,
                        config->max_loop_iterations);
        break;
    }

    hide_wait_box();
    return true;
}

plugin_t PLUGIN = {IDP_INTERFACE_VERSION, 0, init, term, run, "", "", "unxorer", ""};