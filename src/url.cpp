#include "adb/url.hpp"

#include <algorithm>
#include <array>
#include <cstddef>

namespace adb::url {
namespace {

constexpr bool isAlpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
constexpr bool isDigit(char c) { return c >= '0' && c <= '9'; }
constexpr bool isAlnum(char c) { return isAlpha(c) || isDigit(c); }

// `^` separator set, per notes/02 section 2: anything NOT in [A-Za-z0-9_.%-].
constexpr bool isUnreserved(char c) {
    return isAlnum(c) || c == '_' || c == '-' || c == '.' || c == '%';
}

// Parses a decimal port. Empty is accepted and means "scheme default" (0).
bool parsePort(std::string_view s, uint16_t &out) {
    if (s.empty()) return true;
    if (s.size() > 5) return false;
    uint32_t v = 0;
    for (char c : s) {
        if (!isDigit(c)) return false;
        v = v * 10 + static_cast<uint32_t>(c - '0');
    }
    if (v > 65535) return false;
    out = static_cast<uint16_t>(v);
    return true;
}

// Rejects obviously broken authorities (spaces, control chars, stray slashes).
bool plausibleHost(std::string_view h) {
    if (h.empty()) return false;
    for (char c : h) {
        auto u = static_cast<unsigned char>(c);
        if (u <= 0x20 || u == 0x7f) return false;
        if (c == '/' || c == '\\' || c == '?' || c == '#' || c == '@' || c == ':') return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Compact multi-label public-suffix table. Sorted, binary searched. This is
// deliberately NOT the full PSL: it only has to be right often enough for
// third-party determination (notes/02 section 6, `$third-party`).
// ---------------------------------------------------------------------------
constexpr std::array<std::string_view, 39> kMultiSuffix{{
    "ac.uk",  "co.il",     "co.in",  "co.jp",  "co.kr",  "co.nz",  "co.uk",  "co.za",
    "com.ar", "com.au",    "com.br", "com.cn", "com.hk", "com.mx", "com.pl", "com.sg",
    "com.tr", "com.tw",    "com.ua", "edu.au", "github.io", "go.jp", "gov.au", "gov.br",
    "gov.uk", "me.uk",     "ne.jp",  "net.au", "net.br", "net.cn", "net.nz", "net.uk",
    "or.jp",  "org.au",    "org.br", "org.cn", "org.nz", "org.uk", "sch.uk",
}};

bool isMultiLabelSuffix(std::string_view lastTwo) {
    return std::binary_search(kMultiSuffix.begin(), kMultiSuffix.end(), lastTwo);
}

} // namespace

Parts split(std::string_view u) {
    Parts p;
    if (u.empty()) return p;

    const size_t colon = u.find(':');
    if (colon == std::string_view::npos || colon == 0) return p;
    if (!isAlpha(u[0])) return p;
    for (size_t i = 1; i < colon; ++i) {
        const char c = u[i];
        if (!isAlnum(c) && c != '+' && c != '-' && c != '.') return p;
    }
    p.scheme = u.substr(0, colon);

    size_t rest = colon + 1;
    if (u.size() - rest >= 2 && u[rest] == '/' && u[rest + 1] == '/') rest += 2;

    size_t authEnd = u.size();
    for (size_t i = rest; i < u.size(); ++i) {
        const char c = u[i];
        if (c == '/' || c == '?' || c == '#') {
            authEnd = i;
            break;
        }
    }

    std::string_view auth = u.substr(rest, authEnd - rest);
    if (const size_t at = auth.rfind('@'); at != std::string_view::npos)
        auth.remove_prefix(at + 1);

    if (!auth.empty() && auth.front() == '[') { // bracketed IPv6 literal
        const size_t rb = auth.find(']');
        if (rb == std::string_view::npos || rb == 1) return p;
        p.host = auth.substr(1, rb - 1); // brackets stripped
        const std::string_view after = auth.substr(rb + 1);
        if (!after.empty()) {
            if (after.front() != ':') return p;
            if (!parsePort(after.substr(1), p.port)) return p;
        }
    } else {
        const size_t pc = auth.rfind(':');
        if (pc != std::string_view::npos) {
            if (!parsePort(auth.substr(pc + 1), p.port)) return p;
            p.host = auth.substr(0, pc);
        } else {
            p.host = auth;
        }
        if (!plausibleHost(p.host)) {
            p.host = {};
            return p;
        }
    }
    if (p.host.empty()) return p;

    std::string_view tail = u.substr(authEnd);
    if (const size_t hash = tail.find('#'); hash != std::string_view::npos)
        tail = tail.substr(0, hash);
    if (const size_t q = tail.find('?'); q != std::string_view::npos) {
        p.path  = tail.substr(0, q);
        p.query = tail.substr(q + 1);
    } else {
        p.path = tail;
    }

    p.valid = true;
    return p;
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (char &c : out)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

bool isSubdomainOf(std::string_view host, std::string_view domain) {
    if (domain.empty() || host.empty()) return false;
    if (host == domain) return true;
    if (host.size() <= domain.size()) return false;
    const size_t off = host.size() - domain.size();
    return host[off - 1] == '.' && host.compare(off, domain.size(), domain) == 0;
}

std::string_view registrableDomain(std::string_view host) {
    if (host.empty()) return host;
    if (host.back() == '.') host.remove_suffix(1);

    const size_t last = host.rfind('.');
    if (last == std::string_view::npos || last == 0) return host;
    const size_t second = host.rfind('.', last - 1);
    if (second == std::string_view::npos) return host; // exactly two labels

    const std::string_view lastTwo = host.substr(second + 1);
    if (!isMultiLabelSuffix(lastTwo)) return lastTwo;

    if (second == 0) return host; // exactly three labels, all of them needed
    const size_t third = host.rfind('.', second - 1);
    if (third == std::string_view::npos) return host;
    return host.substr(third + 1);
}

bool isThirdParty(std::string_view host, std::string_view sourceHost) {
    if (sourceHost.empty()) return false;
    return registrableDomain(host) != registrableDomain(sourceHost);
}

bool isSeparator(char c) { return !isUnreserved(c); }

} // namespace adb::url
