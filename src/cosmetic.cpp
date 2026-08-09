#include "adb/cosmetic.hpp"

#include "adb/log.hpp"
#include "adb/url.hpp"

#include <atomic>
#include <algorithm>
#include <cstring>
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

// --- token reduction -------------------------------------------------------
//
// A generic selector is only worth emitting when the class/id name it hinges
// on is actually present in the document. `selectorToken` finds the longest
// name the selector *requires*; `pageTokens` collects the names the document
// *has*. Anything we cannot reduce with certainty is emitted unconditionally,
// so the reduction can never hide less than the full list would.

using StrMap = std::unordered_map<std::string, std::vector<std::string>>;

constexpr bool isNameChar(char c) { return isAlnum(c) || c == '_' || c == '-'; }
constexpr bool isSpaceChar(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f';
}
constexpr char lowerChar(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }

// `lower` must already be lowercase.
bool equalsFold(std::string_view s, std::string_view lower) {
    if (s.size() != lower.size()) return false;
    for (size_t i = 0; i < s.size(); ++i)
        if (lowerChar(s[i]) != lower[i]) return false;
    return true;
}

// Longest class/id name the selector requires an element to carry, or "" when
// the selector cannot be reduced. Deliberately gives up on:
//   * selector lists (`.a,.b`) -- the alternatives are not both required
//   * names inside `:not(...)` / `:is(...)` -- not required, or not all of them
//   * `^= *= $= ~= |=` attribute matches -- a token is not a substring test
//   * escaped names (`.foo\/bar`) -- the run we can read is only a prefix
// A `.class` / `#id` elsewhere in the same selector still counts: in
// `div.ad-slot[data-x^="y"]` the element must carry `ad-slot` regardless.
std::string_view selectorToken(std::string_view sel) {
    std::string_view best;
    const size_t n = sel.size();
    size_t i       = 0;
    int paren      = 0;

    auto consider = [&best](std::string_view t) {
        if (t.size() > best.size()) best = t;
    };

    while (i < n) {
        const char c = sel[i];
        if (c == '\\') {
            i += 2;
            continue;
        }
        if (c == '"' || c == '\'') { // stray string outside an attribute
            const char q = c;
            for (++i; i < n && sel[i] != q;) i += (sel[i] == '\\') ? 2 : 1;
            ++i;
            continue;
        }
        if (c == '(') {
            ++paren;
            ++i;
            continue;
        }
        if (c == ')') {
            if (paren > 0) --paren;
            ++i;
            continue;
        }
        if (c == ',' && paren == 0) return {}; // alternatives, none required
        if (c == '[') {
            size_t j = i + 1;
            while (j < n && isSpaceChar(sel[j])) ++j;
            const size_t ns = j;
            while (j < n && isNameChar(sel[j])) ++j;
            const std::string_view attr = sel.substr(ns, j - ns);
            while (j < n && isSpaceChar(sel[j])) ++j;

            bool exact = j < n && sel[j] == '=';
            if (exact) {
                ++j;
            } else if (j + 1 < n && sel[j + 1] == '=' &&
                       (sel[j] == '^' || sel[j] == '*' || sel[j] == '$' || sel[j] == '~' ||
                        sel[j] == '|')) {
                j += 2;
            }
            while (j < n && isSpaceChar(sel[j])) ++j;

            std::string_view val;
            if (j < n && (sel[j] == '"' || sel[j] == '\'')) {
                const char q  = sel[j++];
                const size_t vs = j;
                bool escaped    = false;
                while (j < n && sel[j] != q) {
                    if (sel[j] == '\\') {
                        escaped = true;
                        ++j;
                    }
                    ++j;
                }
                val = sel.substr(vs, std::min(j, n) - vs);
                if (j < n) ++j;
                if (escaped) val = {};
            } else {
                const size_t vs = j;
                while (j < n && sel[j] != ']' && !isSpaceChar(sel[j])) ++j;
                val = sel.substr(vs, j - vs);
            }

            if (exact && paren == 0 && !val.empty() &&
                (equalsFold(attr, "id") || equalsFold(attr, "class")) &&
                val.find_first_of(" \t\r\n\f") == std::string_view::npos)
                consider(val);

            while (j < n && sel[j] != ']') { // trailing flags, e.g. `[id="a" i]`
                if (sel[j] == '"' || sel[j] == '\'') {
                    const char q = sel[j++];
                    while (j < n && sel[j] != q) j += (sel[j] == '\\') ? 2 : 1;
                }
                ++j;
            }
            i = (j < n) ? j + 1 : n;
            continue;
        }
        if ((c == '.' || c == '#') && paren == 0) {
            size_t j = i + 1;
            while (j < n && isNameChar(sel[j])) ++j;
            if (j > i + 1 && (j >= n || sel[j] != '\\')) consider(sel.substr(i + 1, j - i - 1));
            i = j;
            continue;
        }
        ++i;
    }
    return best;
}

// Bounds so a hostile document cannot turn the scan into the slow path we are
// trying to remove.
constexpr size_t kMaxHtmlScan   = 4u * 1024 * 1024;
constexpr size_t kMaxPageTokens = 100000;

// Every class name and id value that appears in `html`, lowercased.
std::unordered_set<std::string> pageTokens(std::string_view html) {
    std::unordered_set<std::string> out;
    const size_t n = std::min(html.size(), kMaxHtmlScan);
    std::string buf;
    out.reserve(512); // a typical document carries a few hundred distinct names

    auto add = [&out, &buf](std::string_view w) {
        if (w.empty() || out.size() >= kMaxPageTokens) return;
        buf.assign(w);
        for (char &ch : buf) ch = lowerChar(ch);
        out.insert(buf);
    };

    // Anchor on '=' and read the attribute name backwards: there are a few
    // thousand '=' in a document but 200 000 characters, and the maximal
    // name-char run ending at the '=' gives the boundary check for free --
    // `data-class` and `itemid` simply do not compare equal.
    size_t p = 0;
    while (p < n) {
        const char *hit = static_cast<const char *>(std::memchr(html.data() + p, '=', n - p));
        if (!hit) break;
        const size_t eq = static_cast<size_t>(hit - html.data());
        p               = eq + 1;

        // Bounded: the longest name we care about is `class`. Without the
        // floor a base64 blob ending in '=' would drag the walk back over
        // kilobytes of name characters for nothing.
        constexpr size_t kMaxAttrName = 6;
        size_t e = eq;
        while (e > 0 && isSpaceChar(html[e - 1])) --e;
        const size_t stop = e > kMaxAttrName ? e - kMaxAttrName : 0;
        size_t s          = e;
        while (s > stop && isNameChar(html[s - 1])) --s;
        if (s > 0 && isNameChar(html[s - 1])) continue; // longer name, e.g. data-class
        const std::string_view name = html.substr(s, e - s);

        bool isClass;
        if (equalsFold(name, "class")) isClass = true;
        else if (equalsFold(name, "id")) isClass = false;
        else continue;

        size_t j = eq + 1;
        while (j < n && isSpaceChar(html[j])) ++j;

        std::string_view val;
        if (j < n && (html[j] == '"' || html[j] == '\'')) {
            const char q    = html[j++];
            const size_t vs = j;
            while (j < n && html[j] != q) ++j;
            val = html.substr(vs, j - vs);
            if (j < n) ++j;
        } else { // learncpp.com serves `<div class=cf_monitor>`
            const size_t vs = j;
            while (j < n && !isSpaceChar(html[j]) && html[j] != '>') ++j;
            val = html.substr(vs, j - vs);
        }
        p = j; // never rescan a '=' that lives inside the value

        if (isClass) {
            for (size_t k = 0; k < val.size();) {
                while (k < val.size() && isSpaceChar(val[k])) ++k;
                const size_t ws = k;
                while (k < val.size() && !isSpaceChar(val[k])) ++k;
                add(val.substr(ws, k - ws));
            }
        } else {
            add(val); // an id is a single name
        }
    }
    return out;
}

// One implementation behind both cssFor() overloads. Exactly one generic
// source is supplied: `generics` (the whole list) or `byToken`+`always`
// filtered by `tokens`. `SpecificMap` is templated only because
// CosmeticIndex::DomainRule is private and cannot be named out here.
template <class SpecificMap>
std::string buildCss(std::string_view rawHost, const SpecificMap &specific,
                     const StrMap &exceptions, const std::vector<std::string> &globalExceptions,
                     const std::vector<std::string> *generics, const StrMap *byToken,
                     const std::vector<std::string> *always,
                     const std::unordered_set<std::string> *tokens) {
    const std::string host = url::lower(rawHost);

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
    for (const std::string &s : globalExceptions) disabled.insert(s);
    for (const std::string &sfx : suffixes) {
        const auto it = exceptions.find(sfx);
        if (it == exceptions.end()) continue;
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

    if (generics) {
        for (const std::string &s : *generics) append(s);
    } else {
        for (const std::string &tok : *tokens) {
            const auto it = byToken->find(tok);
            if (it == byToken->end()) continue;
            for (const std::string &s : it->second) append(s);
        }
        for (const std::string &s : *always) append(s);
    }

    for (const std::string &sfx : suffixes) {
        const auto it = specific.find(sfx);
        if (it == specific.end()) continue;
        for (const auto &dr : it->second) {
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

} // namespace

bool CosmeticIndex::addRule(std::string_view raw) {
    finalized_ = false; // a new rule invalidates the token index
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

void CosmeticIndex::finalize() {
    if (finalized_) return;
    genericByToken_.clear();
    genericAlways_.clear();
    for (const std::string &sel : generic_) {
        const std::string_view tok = selectorToken(sel);
        if (tok.empty()) genericAlways_.push_back(sel);
        else genericByToken_[url::lower(tok)].push_back(sel);
    }
    finalized_ = true;
    ADB_DBG("cosmetic token index: {} generic -> {} tokens + {} always", generic_.size(),
            genericByToken_.size(), genericAlways_.size());
}

std::string CosmeticIndex::cssFor(std::string_view rawHost) const {
    if (rawHost.empty() && generic_.empty()) return {};
    return buildCss(rawHost, specific_, exceptions_, globalExceptions_, &generic_, nullptr, nullptr,
                    nullptr);
}

std::string CosmeticIndex::cssFor(std::string_view rawHost, std::string_view html) const {
    if (!finalized_) {
        // Correct but slow: without the index we cannot tell which generics the
        // page needs, and emitting too few would stop hiding ads.
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true, std::memory_order_relaxed))
            ADB_WARN("cssFor(host, html) called before finalize(); emitting all {} generics",
                     generic_.size());
        return cssFor(rawHost);
    }
    if (rawHost.empty() && generic_.empty()) return {};
    const std::unordered_set<std::string> tokens = pageTokens(html);
    return buildCss(rawHost, specific_, exceptions_, globalExceptions_, nullptr, &genericByToken_,
                    &genericAlways_, &tokens);
}

size_t CosmeticIndex::specificCount() const {
    size_t n = 0;
    for (const auto &kv : specific_) n += kv.second.size();
    return n;
}

} // namespace adb
