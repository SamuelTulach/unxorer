#pragma once

#include <fmt/format.h>
#include <vector>
#include <unordered_set>
#include <chrono>

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
#include "emulator.hpp"
#include "strings.hpp"
#include "results.hpp"
#include "handler.hpp"