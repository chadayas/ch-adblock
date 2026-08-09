#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace adb {

// ---------------------------------------------------------------------------
// Element-hiding rules.
//   example.com##.ad-banner      -> specific
//   ##.ad-banner                 -> generic (applies everywhere)
//   example.com#@#.ad-banner     -> exception, drops the selector for that host
// Everything else (#?#, #$#, #%#, $$) is parsed far enough to be recognised
// and then skipped. See notes/02 section 7.
// ---------------------------------------------------------------------------
class CosmeticIndex {
public:
    // Returns true if the line was a cosmetic rule (whether or not it was
    // supported), so the caller knows not to try parsing it as a network rule.
    bool addRule(std::string_view line);

    // Builds the stylesheet for one document host: all generic selectors plus
    // every selector whose domain list matches, minus every #@# exception for
    // that host. Returns "" when there is nothing to hide.
    // Result is a complete CSS text, e.g. ".a,.b{display:none!important}".
    std::string cssFor(std::string_view host) const;

    size_t genericCount() const { return generic_.size(); }
    size_t specificCount() const;

private:
    struct DomainRule {
        std::string selector;
        std::vector<std::string> exclude; // ~domains
    };

    std::vector<std::string> generic_;
    // host domain -> selectors declared for it
    std::unordered_map<std::string, std::vector<DomainRule>> specific_;
    // host domain -> selectors disabled for it (#@#)
    std::unordered_map<std::string, std::vector<std::string>> exceptions_;
    // selectors disabled everywhere (bare #@#)
    std::vector<std::string> globalExceptions_;
};

} // namespace adb
