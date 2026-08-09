#include "adb/cosmetic.hpp"

#include "adb/log.hpp"
#include "adb/url.hpp"

#include <algorithm>
#include <unordered_set>

namespace adb {
namespace {

constexpr std::string_view kSpace = " \t\r\n";

std::string_view trim(std::string_view s) {
    const size_t b = s.find_first_not_of(kSpace);
    if (b == std::string_view::npos) return {};
    return s.substr(b, s.find_last_not_of(kSpace) - b + 1);
}

enum class Mask { None, Hide, Except, Skip };

struct Found {
    Mask kind = Mask::None;
    size_t pos = 0;
    size_t len = 0;
};

struct MaskName {
    std::string_view text;
    Mask kind;
};
// Longest first so `#@?#` wins over `#@#` at the same offset.
constexpr MaskName kMasks[] = {
    {"#@?#", Mask::Skip}, {"#@$#", Mask::Skip},   {"#@%#", Mask::Skip},
    {"#@#", Mask::Except}, {"#?#", Mask::Skip},   {"#$#", Mask::Skip},
    {"#%#", Mask::Skip},  {"$@$", Mask::Skip},    {"##", Mask::Hide},
    {"$$", Mask::Skip},
};

constexpr bool isAlnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
constexpr bool isDomainListChar(char c) {
    return isAlnum(c) || c == '.' || c == '*' || c == '_' || c == '~' || c == '-' || c == ',';
}

Found findMask(std::string_view line) {
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '#' || c == '$') {
            for (const MaskName &m : kMasks) {
                if (line.compare(i, m.text.size(), m.text) == 0) return {m.kind, i, m.text.size()};
            }
        }
        if (!isDomainListChar(c)) break;
    }
    return {};
}

// Extended-CSS / scriptlet / HTML-rewriting constructs we deliberately do not
// implement -- we only emit plain `display:none` CSS (notes/02 section 7).
constexpr std::string_view kUnsupported[] = {
    ":has(", ":contains(", ":has-text(", ":matches-", ":style(",
    ":xpath(", ":upward(", ":nth-ancestor(", "+js(", "script:", "{",
};

bool selectorUnsupported(std::string_view sel) {
    for (std::string_view bad : kUnsupported)
        if (sel.find(bad) != std::string_view::npos) return true;
    return false;
}

constexpr size_t kMaxCss = 512 * 1024;

} // namespace

bool CosmeticIndex::addRule(std::string_view raw) {
    const std::string_view line = trim(raw);
    const Found f               = findMask(line);
    if (f.kind == Mask::None) return false;
    if (f.kind == Mask::Skip) return true; // recognised, deliberately unsupported

    const std::string_view domainPart = line.substr(0, f.pos);
    const std::string_view selector   = trim(line.substr(f.pos + f.len));
    if (selector.empty()) return false;
    if (selectorUnsupported(selector)) {
        ADB_TRACE("skipping extended selector: {}", line);
        return true;
    }

    std::vector<std::string> include, exclude;
    size_t start = 0;
    while (start <= domainPart.size()) {
        size_t comma = domainPart.find(',', start);
        if (comma == std::string_view::npos) comma = domainPart.size();
        std::string_view d = trim(domainPart.substr(start, comma - start));
        start              = comma + 1;
        if (d.empty()) continue;
        if (d.front() == '~') {
            d.remove_prefix(1);
            if (!d.empty()) exclude.push_back(url::lower(d));
        } else {
            include.push_back(url::lower(d));
        }
    }

    if (f.kind == Mask::Except) {
        if (include.empty()) globalExceptions_.emplace_back(selector);
        else
            for (std::string &d : include) exceptions_[std::move(d)].emplace_back(selector);
        return true;
    }

    if (include.empty()) {
        // A purely negative domain list (`~a.com##.ad`) has no key to file the
        // rule under, and `generic_` cannot carry exclusions -- storing it
        // would hide the element on exactly the host the author exempted.
        if (!exclude.empty()) {
            ADB_TRACE("skipping exclusion-only cosmetic rule: {}", line);
            return true;
        }
        generic_.emplace_back(selector);
        return true;
    }

    for (size_t i = 0; i < include.size(); ++i) {
        DomainRule dr;
        dr.selector = std::string(selector);
        dr.exclude  = (i + 1 == include.size()) ? std::move(exclude) : exclude;
        specific_[std::move(include[i])].push_back(std::move(dr));
    }
    return true;
}

std::string CosmeticIndex::cssFor(std::string_view rawHost) const {
    const std::string host = url::lower(rawHost);
    if (host.empty() && generic_.empty()) return {};

    // host, then every parent suffix: a.b.c -> a.b.c, b.c, c.
    // `std::string` because the frozen maps are keyed by std::string and have
    // no transparent hash; this runs once per document, not per request.
    std::vector<std::string> suffixes;
    for (std::string_view s = host; !s.empty();) {
        suffixes.emplace_back(s);
        const size_t dot = s.find('.');
        if (dot == std::string_view::npos) break;
        s = s.substr(dot + 1);
    }

    std::unordered_set<std::string_view> disabled;
    for (const std::string &s : globalExceptions_) disabled.insert(s);
    for (const std::string &sfx : suffixes) {
        const auto it = exceptions_.find(sfx);
        if (it == exceptions_.end()) continue;
        for (const std::string &s : it->second) disabled.insert(s);
    }

    std::unordered_set<std::string_view> seen;
    std::string out;
    bool truncated = false;

    auto append = [&](std::string_view sel) {
        if (truncated) return;
        if (disabled.count(sel) || !seen.insert(sel).second) return;
        if (out.size() + sel.size() + 1 > kMaxCss) {
            truncated = true;
            return;
        }
        if (!out.empty()) out.push_back(',');
        out.append(sel);
    };

    for (const std::string &s : generic_) append(s);

    for (const std::string &sfx : suffixes) {
        const auto it = specific_.find(sfx);
        if (it == specific_.end()) continue;
        for (const DomainRule &dr : it->second) {
            bool excluded = false;
            for (const std::string &ex : dr.exclude) {
                if (url::isSubdomainOf(host, ex)) {
                    excluded = true;
                    break;
                }
            }
            if (!excluded) append(dr.selector);
        }
    }

    if (truncated) ADB_WARN("cosmetic stylesheet for {} truncated at {} bytes", host, out.size());
    if (out.empty()) return {};
    out.append("{display:none!important}");
    return out;
}

size_t CosmeticIndex::specificCount() const {
    size_t n = 0;
    for (const auto &kv : specific_) n += kv.second.size();
    return n;
}

} // namespace adb
