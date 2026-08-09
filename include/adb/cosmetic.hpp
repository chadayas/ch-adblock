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

    // Same, but keeps only the generic selectors whose class/id token actually
    // occurs in `html`. Real lists carry ~16 000 generic selectors (250 KB of
    // CSS); a given page needs a few dozen. Being a proxy we have the document
    // in hand, so we can do this reduction that a browser extension cannot do
    // before DOM-ready. Selectors that cannot be reduced to a single token
    // (attribute-prefix matches and the like) are always emitted.
    // Domain-specific selectors are always emitted -- there are few per host.
    std::string cssFor(std::string_view host, std::string_view html) const;

    // Call once after all rules are added; builds the token index used by the
    // two-argument cssFor(). Idempotent.
    void finalize();

    size_t genericCount() const { return generic_.size(); }
    size_t specificCount() const;
    // Generic selectors that survive token reduction for `html`.
    size_t genericAlwaysCount() const { return genericAlways_.size(); }

private:
    struct DomainRule {
        std::string selector;
        std::vector<std::string> exclude; // ~domains
    };

    std::vector<std::string> generic_;
    // Lowercased class/id token -> generic selectors keyed on it.
    std::unordered_map<std::string, std::vector<std::string>> genericByToken_;
    // Generic selectors with no single reducible token; always emitted.
    std::vector<std::string> genericAlways_;
    bool finalized_ = false;
    // host domain -> selectors declared for it
    std::unordered_map<std::string, std::vector<DomainRule>> specific_;
    // host domain -> selectors disabled for it (#@#)
    std::unordered_map<std::string, std::vector<std::string>> exceptions_;
    // selectors disabled everywhere (bare #@#)
    std::vector<std::string> globalExceptions_;
};

} // namespace adb
