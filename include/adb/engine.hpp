#pragma once
#include "adb/cosmetic.hpp"
#include "adb/rule.hpp"
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace adb {

struct MatchResult {
    const Rule *rule = nullptr; // nullptr => nothing matched
    bool blocked     = false;   // rule && !rule->isException

    explicit operator bool() const { return rule != nullptr; }
};

struct EngineStats {
    size_t rulesTotal   = 0;
    size_t byShortcut   = 0;
    size_t byDomain     = 0;
    size_t leftovers    = 0;
    size_t badfilters   = 0;
    size_t cosmetic     = 0;
    size_t linesSkipped = 0;
};

// ---------------------------------------------------------------------------
// The three-table index reverse engineered in notes/02 section 4.
//
//   rules_by_shortcut : literal substring -> rules            (bulk)
//   rules_by_domain   : $domain value     -> rules            (no usable shortcut)
//   leftovers         : flat list                             (unindexable)
//
// Call finalize() once after loading; match() is then const and thread-safe.
// ---------------------------------------------------------------------------
class Engine {
public:
    Engine();
    ~Engine();
    Engine(Engine &&) noexcept;
    Engine &operator=(Engine &&) noexcept;

    // Feeds one raw filter-list line. Returns false if the line was skipped.
    bool addLine(std::string_view line, int listId = 0);

    // Loads a filter list file. Returns number of rules accepted.
    size_t loadFile(const std::filesystem::path &p, int listId = 0);

    // Applies $badfilter removals and builds lookup structures.
    // MUST be called before match(). Idempotent.
    void finalize();

    // Highest-priority match for `req`.
    // Precedence: $important blocking > exception > blocking > none.
    MatchResult match(const Request &req) const;

    // The stylesheet to inject for a document served by `host`.
    std::string cosmeticCss(std::string_view host) const { return cosmetic_.cssFor(host); }

    // Preferred form: reduces the ~16 000 generic selectors down to the ones
    // whose class/id token actually appears in this document. Pass the decoded
    // HTML body.
    std::string cosmeticCss(std::string_view host, std::string_view html) const {
        return cosmetic_.cssFor(host, html);
    }

    const EngineStats &stats() const { return stats_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    CosmeticIndex cosmetic_;
    EngineStats stats_;
};

// Maps an HTTP request to a content type using Sec-Fetch-Dest / Accept /
// the URL's file extension, in that order of trust.
ContentType guessContentType(std::string_view secFetchDest, std::string_view accept,
                             std::string_view path);

} // namespace adb
