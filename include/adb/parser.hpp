#pragma once
#include "adb/rule.hpp"
#include <optional>
#include <string>
#include <string_view>

namespace adb {

enum class LineKind {
    Empty,     // blank or comment (`!`, `#` alone, `[Adblock...]`)
    Network,   // a network filtering rule
    Cosmetic,  // ##, #@#, #?#, #$# ...
    Unsupported// recognised syntax we deliberately do not implement
};

// Classifies a raw filter-list line without fully parsing it.
LineKind classify(std::string_view line);

// Parses a network rule. Returns nullopt when the line is not a network rule
// or uses a modifier we cannot honour (unknown modifiers must reject the rule
// outright -- silently ignoring them would under-block or over-block).
std::optional<Rule> parseNetworkRule(std::string_view line);

// Longest literal run in an adblock pattern.
// Break characters: `. ? * + ^ $` (verbatim from the disassembly, notes/01 s5).
// A `|` inside a regex body makes the pattern unindexable -> returns "".
// Runs shorter than `minLen` are ignored.
std::string extractShortcut(std::string_view pattern, bool isRegex, size_t minLen = 3);

} // namespace adb
