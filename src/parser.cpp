#include "adb/parser.hpp"

#include "adb/log.hpp"
#include "adb/url.hpp"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include <algorithm>
#include <cstring>
#include <utility>

namespace adb {

// ===========================================================================
// Regex -- thin PCRE2 wrapper. Declared opaque in rule.hpp, defined here.
// Thread safety: `pcre2_code` is immutable once compiled, so it may be shared;
// only the match data is per-thread. We keep one thread_local scratch block
// sized for 8 capture slots -- we only ever ask a yes/no question, and PCRE2
// reports "matched but ovector too small" as rc == 0, which is still a match.
// ===========================================================================
class Regex {
public:
    Regex() = default;
    Regex(const Regex &)            = delete;
    Regex &operator=(const Regex &) = delete;
    ~Regex() {
        if (code_) pcre2_code_free(code_);
    }

    static std::shared_ptr<Regex> compile(std::string_view body, bool matchCase) {
        uint32_t opts = PCRE2_NO_UTF_CHECK;
        if (!matchCase) opts |= PCRE2_CASELESS;
        int err          = 0;
        PCRE2_SIZE erroff = 0;
        pcre2_code *code = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(body.data()), body.size(),
                                         opts, &err, &erroff, nullptr);
        if (!code) {
            PCRE2_UCHAR buf[256];
            pcre2_get_error_message(err, buf, sizeof(buf));
            ADB_DBG("Bailing on complex pattern: `{}` ({} at {})", body,
                    reinterpret_cast<const char *>(buf), static_cast<size_t>(erroff));
            return nullptr;
        }
        auto r   = std::make_shared<Regex>();
        r->code_ = code;
        return r;
    }

    bool search(std::string_view s) const {
        if (!code_) return false;
        pcre2_match_data *md = scratch();
        if (!md) return false;
        const auto *p = reinterpret_cast<PCRE2_SPTR>(s.empty() ? "" : s.data());
        const int rc  = pcre2_match(code_, p, s.size(), 0, PCRE2_NO_UTF_CHECK, md, nullptr);
        return rc >= 0;
    }

private:
    static pcre2_match_data *scratch() {
        struct Holder {
            pcre2_match_data *md = pcre2_match_data_create(8, nullptr);
            ~Holder() {
                if (md) pcre2_match_data_free(md);
            }
        };
        thread_local Holder h;
        return h.md;
    }

    pcre2_code *code_ = nullptr;
};

namespace {

constexpr std::string_view kSpace = " \t\r\n";

std::string_view trim(std::string_view s) {
    const size_t b = s.find_first_not_of(kSpace);
    if (b == std::string_view::npos) return {};
    return s.substr(b, s.find_last_not_of(kSpace) - b + 1);
}

constexpr bool isAlnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

// Characters legal in the domain-list part that precedes a cosmetic mask.
constexpr bool isDomainListChar(char c) {
    return isAlnum(c) || c == '.' || c == '*' || c == '_' || c == '~' || c == '-' || c == ',';
}

// Cosmetic masks, longest first so `#@?#` wins over `#@#` at the same offset.
constexpr std::string_view kMasks[] = {
    "#@?#", "#@$#", "#@%#", "#@#", "#?#", "#$#", "#%#", "$@$", "##", "$$",
};

// Returns the length of the cosmetic mask starting at `i`, or 0.
size_t maskAt(std::string_view line, size_t i) {
    for (std::string_view m : kMasks)
        if (line.compare(i, m.size(), m) == 0) return m.size();
    return 0;
}

std::string toLower(std::string_view s) { return url::lower(s); }

// Splits on `sep`, honouring backslash escapes.
std::vector<std::string_view> splitUnescaped(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    size_t start = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\') {
            ++i;
            continue;
        }
        if (s[i] == sep) {
            out.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    out.push_back(s.substr(start));
    return out;
}

struct CtName {
    std::string_view name;
    uint32_t bit;
};
constexpr CtName kTypeNames[] = {
    {"document", CT_Document},           {"subdocument", CT_Subdocument},
    {"script", CT_Script},               {"stylesheet", CT_Stylesheet},
    {"css", CT_Stylesheet},              {"image", CT_Image},
    {"font", CT_Font},                   {"media", CT_Media},
    {"xmlhttprequest", CT_XmlHttpRequest}, {"xhr", CT_XmlHttpRequest},
    {"websocket", CT_WebSocket},         {"ping", CT_Ping},
    {"other", CT_Other},                 {"popup", CT_Popup},
};

uint32_t contentTypeBit(std::string_view n) {
    for (const CtName &t : kTypeNames)
        if (t.name == n) return t.bit;
    return 0;
}

// Locates the `$` that opens the modifier section: the LAST unescaped `$` that
// is neither inside a `/regex/` body nor part of an HTML-filtering `$$`.
size_t findModifierSep(std::string_view p) {
    size_t scanFrom = 0;
    if (p.size() >= 2 && p.front() == '/') {
        for (size_t i = p.size(); i-- > 1;) {
            if (p[i] == '/' && (i + 1 == p.size() || p[i + 1] == '$')) {
                scanFrom = i + 1;
                break;
            }
        }
    }
    for (size_t i = p.size(); i-- > scanFrom;) {
        if (p[i] != '$') continue;
        if (i > 0 && p[i - 1] == '\\') continue;
        if (i > 0 && p[i - 1] == '$') continue;
        if (i + 1 < p.size() && p[i + 1] == '$') continue;
        return i;
    }
    return std::string_view::npos;
}

// ---------------------------------------------------------------------------
// The glob matcher. `*` = any run, `^` = a separator char or end-of-string,
// everything else literal. Iterative with a single backtrack point, so no
// recursion and no allocation in the hot path.
// ---------------------------------------------------------------------------
bool globAt(std::string_view p, std::string_view s, size_t si, bool anchorEnd) {
    size_t pi = 0, star = std::string_view::npos, ss = 0;
    while (true) {
        if (pi < p.size()) {
            const char pc = p[pi];
            if (pc == '*') {
                star = ++pi;
                ss   = si;
                continue;
            }
            if (si < s.size() && (pc == s[si] || (pc == '^' && url::isSeparator(s[si])))) {
                ++pi;
                ++si;
                continue;
            }
            if (pc == '^' && si == s.size()) { // `^` also matches end-of-URL
                ++pi;
                continue;
            }
        } else if (!anchorEnd || si == s.size()) {
            return true;
        }
        if (star != std::string_view::npos && ss < s.size()) {
            si = ++ss;
            pi = star;
            continue;
        }
        return false;
    }
}

bool globSearch(std::string_view p, std::string_view s, bool anchorEnd) {
    if (p.empty()) return true;
    const char c0      = p.front();
    const bool literal = (c0 != '*' && c0 != '^');
    for (size_t i = 0; i <= s.size(); ++i) {
        if (literal) {
            if (i >= s.size()) return false;
            const void *hit = std::memchr(s.data() + i, c0, s.size() - i);
            if (!hit) return false;
            i = static_cast<size_t>(static_cast<const char *>(hit) - s.data());
        }
        if (globAt(p, s, i, anchorEnd)) return true;
    }
    return false;
}

// Host span of an already-lowercased absolute URL, userinfo removed.
void hostSpan(std::string_view u, size_t &hs, size_t &he) {
    const size_t p = u.find("://");
    hs             = (p == std::string_view::npos) ? 0 : p + 3;
    he             = u.size();
    for (size_t i = hs; i < u.size(); ++i) {
        const char c = u[i];
        if (c == '/' || c == '?' || c == '#') {
            he = i;
            break;
        }
    }
    const size_t at = u.rfind('@', he == 0 ? 0 : he - 1);
    if (at != std::string_view::npos && at >= hs && at < he) hs = at + 1;
}

} // namespace

// ===========================================================================
// Small public-ish helpers
// ===========================================================================

Method methodFromString(std::string_view s) {
    struct Entry {
        std::string_view n;
        Method m;
    };
    static constexpr Entry kMethods[] = {
        {"get", M_GET},         {"post", M_POST},       {"put", M_PUT},
        {"delete", M_DELETE},   {"head", M_HEAD},       {"options", M_OPTIONS},
        {"patch", M_PATCH},     {"connect", M_CONNECT}, {"trace", M_TRACE},
    };
    char buf[8];
    if (s.empty() || s.size() > sizeof(buf)) return M_None;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        buf[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }
    const std::string_view key(buf, s.size());
    for (const Entry &e : kMethods)
        if (e.n == key) return e.m;
    return M_None;
}

Request Request::make(std::string_view u, std::string_view srcHost, ContentType t, Method m) {
    Request r;
    r.url        = url::lower(u);
    r.sourceHost = url::lower(srcHost);
    const url::Parts parts = url::split(r.url);
    if (parts.valid) r.host.assign(parts.host);
    r.type       = t;
    r.method     = m;
    r.thirdParty = url::isThirdParty(r.host, r.sourceHost);
    return r;
}

// ===========================================================================
// classify()
// ===========================================================================

LineKind classify(std::string_view raw) {
    const std::string_view line = trim(raw);
    if (line.empty()) return LineKind::Empty;
    if (line.front() == '!' || line.front() == '[') return LineKind::Empty;
    if (line == "#") return LineKind::Empty;
    if (line.size() >= 2 && line[0] == '#' && line[1] == ' ') return LineKind::Empty;

    // A mask only counts when everything before it could be a domain list --
    // that is what keeps `||x.com/a##b` a network rule.
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if ((c == '#' || c == '$') && maskAt(line, i) != 0) return LineKind::Cosmetic;
        if (!isDomainListChar(c)) break;
    }
    return LineKind::Network;
}

// ===========================================================================
// extractShortcut()
// ===========================================================================

std::string extractShortcut(std::string_view pattern, bool isRegex, size_t minLen) {
    size_t bestOff = 0, bestLen = 0, curOff = 0, curLen = 0;

    // `drop` trims the trailing char of the run first: in a regex, `x?` / `x*`
    // makes that char optional, so it cannot be part of a guaranteed literal.
    auto close = [&](size_t drop) {
        if (drop >= curLen) curLen = 0;
        else curLen -= drop;
        if (curLen > bestLen) {
            bestLen = curLen;
            bestOff = curOff;
        }
        curLen = 0;
    };

    bool inClass  = false; // regex only: inside [...]
    unsigned depth = 0;    // regex only: parenthesis nesting
    for (size_t i = 0; i < pattern.size(); ++i) {
        const char c = pattern[i];

        if (isRegex) {
            if (c == '\\') {
                close(0);
                ++i; // the escaped char is not a literal run member
                continue;
            }
            if (c == '[') inClass = true;
            else if (c == ']') inClass = false;
            else if (c == '|' && !inClass)
                return {}; // alternation -> unindexable (notes/02 section 3)
            else if (c == '(' && !inClass) ++depth;
            else if (c == ')' && !inClass && depth) --depth;
        }

        bool brk = (c == '.' || c == '?' || c == '*' || c == '+' || c == '^' || c == '$');
        if (isRegex && !brk)
            brk = (c == '|' || c == '/' || c == '(' || c == ')' || c == '[' || c == ']' ||
                   c == '{' || c == '}');

        if (brk) {
            close(isRegex && (c == '?' || c == '*' || c == '{') ? 1 : 0);
            continue;
        }
        // Anything inside a group is conditional; never index it.
        if (isRegex && depth) {
            close(0);
            continue;
        }
        if (curLen == 0) curOff = i;
        ++curLen;
    }
    close(0);

    if (bestLen < minLen) return {};
    return std::string(pattern.substr(bestOff, bestLen));
}

// ===========================================================================
// Rule::matchesPattern()
// ===========================================================================

bool Rule::matchesPattern(std::string_view u) const {
    if (isRegex) return re && re->search(u);
    if (pattern.empty()) return true;

    const std::string_view pat(pattern);

    if (domainAnchor) {
        size_t hs = 0, he = 0;
        hostSpan(u, hs, he);
        for (size_t i = hs; i < he; ++i) {
            if (i != hs && u[i - 1] != '.') continue;
            if (globAt(pat, u, i, anchorEnd)) return true;
        }
        return false;
    }
    if (anchorStart) return globAt(pat, u, 0, anchorEnd);
    return globSearch(pat, u, anchorEnd);
}

// ===========================================================================
// parseNetworkRule()
// ===========================================================================

std::optional<Rule> parseNetworkRule(std::string_view raw) {
    const std::string_view line = trim(raw);
    if (line.empty()) return std::nullopt;

    Rule r;
    r.text = std::string(line);

    std::string_view p = line;
    if (p.size() >= 2 && p[0] == '@' && p[1] == '@') {
        r.isException = true;
        p.remove_prefix(2);
    }
    if (p.empty()) return std::nullopt;

    const size_t sep            = findModifierSep(p);
    std::string_view patternRaw = (sep == std::string_view::npos) ? p : p.substr(0, sep);
    const std::string_view mods = (sep == std::string_view::npos) ? std::string_view{}
                                                                  : p.substr(sep + 1);

    // ---- modifiers -------------------------------------------------------
    bool sawAll = false;
    if (sep != std::string_view::npos) {
        if (mods.empty()) return std::nullopt;
        for (std::string_view tokRaw : splitUnescaped(mods, ',')) {
            std::string_view tok = trim(tokRaw);
            if (tok.empty()) continue;
            bool neg = false;
            if (tok.front() == '~') {
                neg = true;
                tok.remove_prefix(1);
            }
            std::string_view name = tok, value;
            bool hasValue         = false;
            if (const size_t eq = tok.find('='); eq != std::string_view::npos) {
                name     = tok.substr(0, eq);
                value    = tok.substr(eq + 1);
                hasValue = true;
            }
            if (name.empty()) return std::nullopt;

            if (const uint32_t bit = contentTypeBit(name); bit != 0) {
                if (hasValue) return std::nullopt;
                if (neg) r.typesDeny |= bit;
                else r.typesAllow |= bit;
                continue;
            }
            if (name == "third-party" || name == "3p") {
                if (hasValue) return std::nullopt;
                r.thirdParty = neg ? ThirdParty::NotOnly : ThirdParty::Only;
                continue;
            }
            if (name == "domain" || name == "from") {
                if (!hasValue || value.empty() || neg) return std::nullopt;
                for (std::string_view d : splitUnescaped(value, '|')) {
                    d = trim(d);
                    if (d.empty()) continue;
                    if (d.front() == '~') r.excludeDomains.push_back(toLower(d.substr(1)));
                    else r.includeDomains.push_back(toLower(d));
                }
                if (r.includeDomains.empty() && r.excludeDomains.empty()) return std::nullopt;
                continue;
            }
            if (name == "denyallow") {
                if (!hasValue || value.empty() || neg) return std::nullopt;
                for (std::string_view d : splitUnescaped(value, '|')) {
                    d = trim(d);
                    if (!d.empty()) r.denyAllow.push_back(toLower(d));
                }
                if (r.denyAllow.empty()) return std::nullopt;
                continue;
            }
            if (name == "method") {
                if (!hasValue || value.empty() || neg) return std::nullopt;
                for (std::string_view mv : splitUnescaped(value, '|')) {
                    mv = trim(mv);
                    if (mv.empty()) continue;
                    bool mneg = false;
                    if (mv.front() == '~') {
                        mneg = true;
                        mv.remove_prefix(1);
                    }
                    const Method m = methodFromString(mv);
                    if (m == M_None) return std::nullopt;
                    if (mneg) r.methodsDeny |= static_cast<uint16_t>(m);
                    else r.methods |= static_cast<uint16_t>(m);
                }
                continue;
            }
            if (name == "match-case") {
                if (hasValue || neg) return std::nullopt;
                r.matchCase = true;
                continue;
            }
            if (name == "important") {
                if (hasValue || neg) return std::nullopt;
                r.isImportant = true;
                continue;
            }
            if (name == "badfilter") {
                if (hasValue || neg) return std::nullopt;
                r.isBadfilter = true;
                continue;
            }
            if (name == "removeparam") {
                if (neg) return std::nullopt;
                if (!hasValue) {
                    r.removeAllParams = true;
                    continue;
                }
                if (value.empty()) return std::nullopt;
                // `~p` (invert) and `/re/` (regex) forms are not implemented;
                // honouring the rule while ignoring the form would be a bug.
                if (value.front() == '~' || value.front() == '/') return std::nullopt;
                for (std::string_view v : splitUnescaped(value, '|')) {
                    v = trim(v);
                    if (v.empty() || v.front() == '~' || v.front() == '/') return std::nullopt;
                    r.removeParams.emplace_back(v);
                }
                if (r.removeParams.empty()) return std::nullopt;
                continue;
            }
            if (name == "all") {
                if (hasValue || neg) return std::nullopt;
                sawAll = true;
                continue;
            }
            // csp, replace, redirect, hls, cookie, app, header, stealth,
            // jsonprune, permissions, urltransform, ... -- reject outright.
            ADB_TRACE("Called with rule: {} -- option {} is not supported", line, name);
            return std::nullopt;
        }
    }
    if (sawAll) {
        r.typesAllow = 0;
        r.typesDeny  = 0;
    }

    // ---- pattern ---------------------------------------------------------
    if (patternRaw.size() >= 3 && patternRaw.front() == '/' && patternRaw.back() == '/') {
        r.isRegex = true;
        r.pattern = std::string(patternRaw.substr(1, patternRaw.size() - 2));
        r.re      = Regex::compile(r.pattern, r.matchCase);
        if (!r.re) return std::nullopt;
    } else {
        if (patternRaw.size() >= 2 && patternRaw[0] == '|' && patternRaw[1] == '|') {
            r.domainAnchor = true;
            patternRaw.remove_prefix(2);
        } else if (!patternRaw.empty() && patternRaw.front() == '|') {
            r.anchorStart = true;
            patternRaw.remove_prefix(1);
        }
        if (!patternRaw.empty() && patternRaw.back() == '|') {
            r.anchorEnd = true;
            patternRaw.remove_suffix(1);
        }
        r.pattern = r.matchCase ? std::string(patternRaw) : toLower(patternRaw);
    }

    if (r.pattern.empty() && r.includeDomains.empty() && r.excludeDomains.empty())
        return std::nullopt;

    r.shortcut = extractShortcut(r.pattern, r.isRegex);
    // The engine matches against a lowercased URL, so the index key must be
    // lowercase too. Non-regex patterns already are; regex bodies are not.
    if (!r.matchCase)
        for (char &c : r.shortcut)
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    ADB_TRACE("Pattern: `{}`, longest shortcut: `{}`", r.pattern, r.shortcut);
    return r;
}

} // namespace adb
