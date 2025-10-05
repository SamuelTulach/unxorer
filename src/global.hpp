#pragma once

#define NOMINMAX
#include <fmt/format.h>
#include <vector>
#include <array>
#include <algorithm>
#include <unordered_set>
#include <chrono>
#include <utility>
#include <atomic>
#include <optional>

#pragma warning(push, 0)
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <gdl.hpp>
#include <allins.hpp>
#include <pro.h>
#pragma warning(pop)

#include <unicorn/unicorn.h>

#include "console.hpp"
#include "logger.hpp"
#include "string_result.hpp"
#include "instruction_classifier.hpp"
#include "branch_manager.hpp"
#include "register_mapper.hpp"
#include "vector_operations.hpp"
#include "emulator.hpp"
#include "strings.hpp"
#include "results.hpp"
#include "handler.hpp"