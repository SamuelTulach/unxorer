#include "global.hpp"

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

    emulator::reset();

    enum scope
    {
        S_FUNC = 0,
        S_EVERY_FUNC,
        S_CUR,
        S_ENTRY
    };

    static const char form[] = "unxorer\n"
                               "Start from:\n"
                               "<#Current function:R>\n"
                               "<#Every function (very slow!):R>\n"
                               "<#Current cursor location:R>\n"
                               "<#Entry point:R>>\n"
                               "\n"
                               "Limits (per branch):\n"
                               "<Max time (ms):\t      D:20:10::>\n"
                               "<Max instructions:\t   D:20:10::>\n";

    uval_t max_time = 10000;
    uval_t max_instr_count = 3000;
    int scope = S_FUNC;
    if (!ask_form(form, &scope, &max_time, &max_instr_count))
        return false;

    show_wait_box("Initializing");

    switch (scope)
    {
    case S_FUNC: {
        const func_t* func = get_func(get_screen_ea());
        if (!func)
        {
            warning("No function under cursor");
            break;
        }

        emulator::run(func->start_ea, max_time, max_instr_count);
        results::display(emulator::string_list);
        break;
    }
    case S_EVERY_FUNC: {
        const size_t total = get_func_qty();
        if (total == 0)
        {
            warning("No functions in the database");
            break;
        }

        logger::print("running on {0} functions in database", total);

        emulator::should_update_dialog = false;

        for (size_t i = 0; i < total; i++)
        {
            const ea_t start = getn_func(i)->start_ea;
            replace_wait_box("Emulating function %zu/%zu at 0x%a", i + 1, total, start);

            emulator::run(start, max_time, max_instr_count);

            if (user_cancelled())
                break;
        }

        results::display(emulator::string_list);
        break;
    }
    case S_CUR: {
        emulator::run(get_screen_ea(), max_time, max_instr_count);
        results::display(emulator::string_list);
        break;
    }
    case S_ENTRY:
        emulator::run(inf_get_start_ea(), max_time, max_instr_count);
        results::display(emulator::string_list);
        break;
    }

    hide_wait_box();
    return true;
}

plugin_t PLUGIN = {IDP_INTERFACE_VERSION, 0, init, term, run, "", "", "unxorer", ""};