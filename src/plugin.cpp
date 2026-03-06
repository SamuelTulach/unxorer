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

static size_t resolve_thread_count(size_t total_tasks)
{
    const unsigned int hw = std::thread::hardware_concurrency();
    const size_t preferred = (hw == 0) ? 4 : static_cast<size_t>(hw);
    return std::max<size_t>(1, std::min(preferred, total_tasks));
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

    default:
        return std::nullopt;
    }
}

static void run_on_function(ea_t start, const emulation_config& config,
                            const emulator::image_snapshot_t& image_snapshot,
                            const emulator::instruction_snapshot_t& instruction_snapshot)
{
    emulator emu(image_snapshot, instruction_snapshot, true);
    if (!emu.is_ready())
    {
        warning("Failed to initialize emulator");
        return;
    }

    emu.should_update_dialog = true;
    replace_wait_box("Emulating function at 0x%llx", static_cast<unsigned long long>(start));
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

static void run_on_all_functions(const emulation_config& config, const emulator::image_snapshot_t& image_snapshot,
                                 const emulator::instruction_snapshot_t& instruction_snapshot)
{
    const std::vector<ea_t> starts = collect_function_starts();
    if (starts.empty())
    {
        warning("No functions in the database");
        return;
    }

    const size_t total = starts.size();
    logger::info("running on {0} functions in database", total);

    std::atomic<size_t> next_index = 0;
    std::atomic<size_t> completed = 0;
    std::atomic_bool stop_requested = false;
    std::atomic<size_t> limit_hit_functions = 0;
    std::atomic<size_t> limit_hit_total = 0;

    const size_t thread_count = resolve_thread_count(total);
    std::vector<std::unordered_set<found_string_t, found_string_hash>> partial_results(thread_count);
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (size_t worker_id = 0; worker_id < thread_count; ++worker_id)
    {
        workers.emplace_back([&, worker_id]() {
            emulator emu(image_snapshot, instruction_snapshot, false);
            if (!emu.is_ready())
            {
                stop_requested.store(true, std::memory_order_relaxed);
                return;
            }

            emu.should_update_dialog = false;

            auto& local = partial_results[worker_id];
            local.reserve(total / thread_count + 1);

            for (;;)
            {
                if (stop_requested.load(std::memory_order_relaxed))
                    break;

                const size_t index = next_index.fetch_add(1, std::memory_order_relaxed);
                if (index >= total)
                    break;

                emu.run(starts[index], config.max_time_ms, config.max_instructions, config.max_loop_iterations,
                        &stop_requested);

                if (emu.transient_limit_reached())
                {
                    limit_hit_functions.fetch_add(1, std::memory_order_relaxed);
                    limit_hit_total.fetch_add(emu.transient_limit_hits(), std::memory_order_relaxed);
                }

                const auto& found = emu.get_string_list();
                local.insert(found.begin(), found.end());
                completed.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    while (completed.load(std::memory_order_relaxed) < total)
    {
        if (stop_requested.load(std::memory_order_relaxed))
            break;

        const size_t done = completed.load(std::memory_order_relaxed);
        replace_wait_box("Emulating %zu/%zu functions using %zu threads", done, total, thread_count);

        if (user_cancelled())
        {
            stop_requested.store(true, std::memory_order_relaxed);
            break;
        }

        qsleep(100);
    }

    for (auto& worker : workers)
        worker.join();

    std::unordered_set<found_string_t, found_string_hash> aggregated;
    aggregated.reserve(total);
    for (auto& partial : partial_results)
        aggregated.insert(partial.begin(), partial.end());

    const size_t hit_functions = limit_hit_functions.load(std::memory_order_relaxed);
    if (hit_functions > 0)
    {
        const size_t hit_total = limit_hit_total.load(std::memory_order_relaxed);
        logger::info("warning: transient mapping limit reached in {0} function runs ({1} total hits)", hit_functions,
                     hit_total);
    }

    replace_wait_box("Emulation finished using %zu threads", thread_count);

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

    const auto image_snapshot = emulator::capture_image_snapshot();
    if (!image_snapshot)
    {
        warning("Failed to capture image snapshot");
        hide_wait_box();
        return false;
    }

    replace_wait_box("Creating instruction cache");
    const auto instruction_snapshot =
        emulator::capture_instruction_snapshot(image_snapshot->image_min, image_snapshot->image_max);
    if (!instruction_snapshot)
    {
        warning("Failed to build instruction snapshot");
        hide_wait_box();
        return false;
    }

    if (config->scope == emulation_scope::every_function)
    {
        run_on_all_functions(*config, *image_snapshot, *instruction_snapshot);
    }
    else if (const auto start = resolve_single_start(config->scope); start.has_value())
    {
        run_on_function(*start, *config, *image_snapshot, *instruction_snapshot);
    }

    hide_wait_box();
    return true;
}

plugin_t PLUGIN = {IDP_INTERFACE_VERSION, 0, init, nullptr, run, "", "", "unxorer", ""};
