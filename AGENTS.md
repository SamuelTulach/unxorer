# Agents Instructions
This is an IDA Pro plugin for deobfuscating stack strings. It works by running an emulator and checking for valid strings on stack, while forcing branching into every feasible execution path.

## Comments

Use comments to explain **why a decision was made**, not to restate **what the code already shows**. Avoid narrating obvious operations. Prefer concise explanations that provide context, constraints, or non‑obvious reasoning.

Write a comment only when it helps a reader understand intent, architectural decisions, or unusual behavior.

### Bad example

```cpp
// Remap module
auto mod = remap_module(target_address);
```

This comment only repeats what the code already states.

### Good example

```cpp
// Memory map in firmware context does not contain current module, therefore switching context
// while running this code would result in access violation
// We can remap our current module into a new allocation that is mapped in firmware context and
// then call into it
auto mod = remap_module(target_address);
```

## Avoid Overly Defensive Code

Do not add defensive checks for conditions that **cannot occur accordingto the API or program invariants**. Redundant validation adds noise and makes the code harder to read and maintain.

Only guard against cases that are realistically possible or externally influenced.

### Bad example

```cpp
image_min_ = inf_get_min_ea();
image_max_ = inf_get_max_ea();

if (image_max_ <= image_min_)
{
    logger::info("invalid image range {0:x} - {1:x}", image_min_, image_max_);
    cleanup();
    return;
}
```

## Formatting
After editing any C++ code, always run clang-format:
```
clang-format -i -style=file src/file.cpp
```
