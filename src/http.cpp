#include "adb/http.hpp"

#include <cstdlib>
#include <cstring>
#include <zlib.h>

namespace adb::http {
namespace {

constexpr size_t kMaxHeadBytes = 64u * 1024;
constexpr size_t kMaxHeaders   = 200;
constexpr size_t kZStep        = 64u * 1024;
constexpr size_t kZMaxOut      = 64u * 1024 * 1024;

constexpr char lowerc(char c) { return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c; }

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (lowerc(a[i]) != lowerc(b[i])) return false;
    return true;
}

// Case-insensitive substring search; no allocation.
bool icontains(std::string_view hay, std::string_view needle) {
    if (needle.empty()) return true;
    if (hay.size() < needle.size()) return false;
    const size_t last = hay.size() - needle.size();
    for (size_t i = 0; i <= last; ++i) {
        size_t j = 0;
        while (j < needle.size() && lowerc(hay[i + j]) == lowerc(needle[j])) ++j;
        if (j == needle.size()) return true;
    }
    return false;
}

std::string_view trimOws(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
    return s.substr(b, e - b);
}

int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parses "123" as a size. Returns false on empty / non-digit / overflow.
bool parseDec(std::string_view s, size_t &out) {
    if (s.empty()) return false;
    size_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        if (v > (SIZE_MAX - size_t(c - '0')) / 10) return false;
        v = v * 10 + size_t(c - '0');
    }
    out = v;
    return true;
}

// Splits the head at CRLFCRLF and fills `headers`. `startLine` aliases `buf`.
// Same return convention as parseRequestHead().
long parseHeadCommon(std::string_view buf, std::string_view &startLine, Headers &headers) {
    const size_t end = buf.find("\r\n\r\n");
    if (end == std::string_view::npos) {
        if (buf.size() > kMaxHeadBytes) return -1;
        return 0;
    }
    const size_t total = end + 4;
    if (total > kMaxHeadBytes) return -1;

    // block ends with the CRLF that terminates the last header line.
    std::string_view block = buf.substr(0, end + 2);
    size_t p = block.find("\r\n");
    if (p == std::string_view::npos) return -1;
    startLine = block.substr(0, p);
    if (startLine.empty()) return -1;
    p += 2;

    headers.items.clear();
    while (p < block.size()) {
        const size_t nl = block.find("\r\n", p);
        if (nl == std::string_view::npos) return -1;
        std::string_view line = block.substr(p, nl - p);
        p = nl + 2;
        if (line.empty()) return -1;
        if (line[0] == ' ' || line[0] == '\t') return -1; // obs-fold: rejected
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos) return -1;
        std::string_view name = trimOws(line.substr(0, colon));
        if (name.empty()) return -1;
        if (headers.items.size() >= kMaxHeaders) return -1;
        headers.items.push_back({std::string(name), std::string(trimOws(line.substr(colon + 1)))});
    }
    return static_cast<long>(total);
}

void appendHeaders(std::string &out, const Headers &h) {
    for (const Header &x : h.items) {
        out += x.name;
        out += ": ";
        out += x.value;
        out += "\r\n";
    }
}

// 43-byte 1x1 transparent GIF89a.
constexpr unsigned char kGif[] = {
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61,             // "GIF89a"
    0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,       // logical screen descriptor
    0x00, 0x00, 0x00, 0xff, 0xff, 0xff,             // global colour table
    0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, // graphic control ext
    0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // image descriptor
    0x02, 0x02, 0x44, 0x01, 0x00,                   // LZW data
    0x3b                                            // trailer
};
static_assert(sizeof(kGif) == 43, "transparent GIF must be 43 bytes");

} // namespace

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

std::string_view Headers::get(std::string_view name) const {
    for (const Header &h : items)
        if (iequals(h.name, name)) return h.value;
    return {};
}

bool Headers::has(std::string_view name) const {
    for (const Header &h : items)
        if (iequals(h.name, name)) return true;
    return false;
}

void Headers::set(std::string_view name, std::string_view value) {
    bool done = false;
    for (size_t i = 0; i < items.size();) {
        if (iequals(items[i].name, name)) {
            if (!done) {
                items[i].value.assign(value);
                done = true;
                ++i;
            } else {
                items.erase(items.begin() + static_cast<long>(i)); // drop duplicates
            }
        } else {
            ++i;
        }
    }
    if (!done) items.push_back({std::string(name), std::string(value)});
}

void Headers::remove(std::string_view name) {
    for (size_t i = 0; i < items.size();) {
        if (iequals(items[i].name, name))
            items.erase(items.begin() + static_cast<long>(i));
        else
            ++i;
    }
}

void Headers::append(std::string_view name, std::string_view value) {
    items.push_back({std::string(name), std::string(value)});
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

std::string Request::serialize() const {
    std::string out;
    out.reserve(64 + target.size() + body.size() + headers.items.size() * 32);
    out += method;
    out += ' ';
    out += target;
    out += ' ';
    out += version.empty() ? "HTTP/1.1" : version;
    out += "\r\n";
    appendHeaders(out, headers);
    out += "\r\n";
    out += body;
    return out;
}

std::string Response::serialize() const {
    std::string out;
    out.reserve(64 + body.size() + headers.items.size() * 32);
    out += version.empty() ? "HTTP/1.1" : version;
    out += ' ';
    out += std::to_string(status);
    out += ' ';
    out += reason;
    out += "\r\n";
    appendHeaders(out, headers);
    out += "\r\n";
    out += body;
    return out;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

long parseRequestHead(std::string_view buf, Request &out) {
    std::string_view line;
    Headers headers;
    const long n = parseHeadCommon(buf, line, headers);
    if (n <= 0) return n;

    const size_t s1 = line.find(' ');
    if (s1 == std::string_view::npos || s1 == 0) return -1;
    const size_t s2 = line.find(' ', s1 + 1);
    if (s2 == std::string_view::npos) return -1;
    std::string_view method = line.substr(0, s1);
    std::string_view target = line.substr(s1 + 1, s2 - s1 - 1);
    std::string_view version = trimOws(line.substr(s2 + 1));
    if (target.empty() || version.empty()) return -1;
    if (version.rfind("HTTP/", 0) != 0) return -1;

    out.method.assign(method);
    out.target.assign(target);
    out.version.assign(version);
    out.headers = std::move(headers);
    out.body.clear();
    return n;
}

long parseResponseHead(std::string_view buf, Response &out) {
    std::string_view line;
    Headers headers;
    const long n = parseHeadCommon(buf, line, headers);
    if (n <= 0) return n;

    const size_t s1 = line.find(' ');
    if (s1 == std::string_view::npos || s1 == 0) return -1;
    std::string_view version = line.substr(0, s1);
    if (version.rfind("HTTP/", 0) != 0) return -1;
    std::string_view rest = line.substr(s1 + 1);
    const size_t s2 = rest.find(' ');
    std::string_view code = (s2 == std::string_view::npos) ? rest : rest.substr(0, s2);
    size_t status = 0;
    if (!parseDec(code, status) || status < 100 || status > 599) return -1;

    out.version.assign(version);
    out.status = static_cast<int>(status);
    out.reason.assign(s2 == std::string_view::npos ? std::string_view{} : trimOws(rest.substr(s2 + 1)));
    out.headers = std::move(headers);
    out.body.clear();
    return n;
}

// ---------------------------------------------------------------------------
// Body framing
// ---------------------------------------------------------------------------

BodyPlan planRequestBody(const Request &r) {
    BodyPlan p;
    if (icontains(r.headers.get("Transfer-Encoding"), "chunked")) {
        p.kind = BodyPlan::Kind::Chunked;
        return p;
    }
    std::string_view cl = r.headers.get("Content-Length");
    size_t n = 0;
    if (!cl.empty() && parseDec(trimOws(cl), n)) {
        p.kind   = BodyPlan::Kind::Length;
        p.length = n;
        return p;
    }
    p.kind = BodyPlan::Kind::None;
    return p;
}

BodyPlan planResponseBody(const Response &r, std::string_view requestMethod) {
    BodyPlan p;
    if (iequals(requestMethod, "HEAD") || (r.status >= 100 && r.status < 200) || r.status == 204 ||
        r.status == 304) {
        p.kind = BodyPlan::Kind::None;
        return p;
    }
    if (iequals(requestMethod, "CONNECT") && r.status >= 200 && r.status < 300) {
        p.kind = BodyPlan::Kind::None;
        return p;
    }
    if (icontains(r.headers.get("Transfer-Encoding"), "chunked")) {
        p.kind = BodyPlan::Kind::Chunked;
        return p;
    }
    std::string_view cl = r.headers.get("Content-Length");
    size_t n = 0;
    if (!cl.empty() && parseDec(trimOws(cl), n)) {
        p.kind   = BodyPlan::Kind::Length;
        p.length = n;
        return p;
    }
    p.kind = BodyPlan::Kind::UntilClose;
    return p;
}

std::optional<std::string> dechunk(std::string_view buf, size_t &consumed) {
    std::string out;
    size_t p = 0;
    for (;;) {
        const size_t nl = buf.find("\r\n", p);
        if (nl == std::string_view::npos) return std::nullopt;
        std::string_view line = buf.substr(p, nl - p);
        const size_t semi = line.find(';'); // chunk extensions are ignored
        std::string_view hex = trimOws(semi == std::string_view::npos ? line : line.substr(0, semi));
        if (hex.empty() || hex.size() > 16) return std::nullopt;
        size_t sz = 0;
        for (char c : hex) {
            const int d = hexval(c);
            if (d < 0) return std::nullopt;
            sz = sz * 16 + static_cast<size_t>(d);
        }
        p = nl + 2;

        if (sz == 0) { // last chunk: consume the trailer section
            for (;;) {
                const size_t tnl = buf.find("\r\n", p);
                if (tnl == std::string_view::npos) return std::nullopt;
                const bool blank = (tnl == p);
                p = tnl + 2;
                if (blank) break;
            }
            consumed = p;
            return out;
        }

        if (buf.size() < p + sz + 2) return std::nullopt;
        out.append(buf.substr(p, sz));
        p += sz;
        if (buf.substr(p, 2) != "\r\n") return std::nullopt;
        p += 2;
    }
}

// ---------------------------------------------------------------------------
// zlib
// ---------------------------------------------------------------------------

std::optional<std::string> gunzip(std::string_view in) {
    if (in.empty()) return std::string{};

    z_stream s{};
    if (inflateInit2(&s, 15 + 32) != Z_OK) return std::nullopt; // auto gzip/zlib detect
    s.next_in  = reinterpret_cast<Bytef *>(const_cast<char *>(in.data()));
    s.avail_in = static_cast<uInt>(in.size());

    std::string out;
    size_t used = 0;
    for (;;) {
        if (out.size() - used < kZStep) out.resize(used + kZStep);
        s.next_out  = reinterpret_cast<Bytef *>(out.data() + used);
        s.avail_out = static_cast<uInt>(out.size() - used);
        const int rc = inflate(&s, Z_NO_FLUSH);
        used = out.size() - s.avail_out;
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK && rc != Z_BUF_ERROR) {
            inflateEnd(&s);
            return std::nullopt;
        }
        if (used > kZMaxOut) {
            inflateEnd(&s);
            return std::nullopt;
        }
        if (s.avail_in == 0 && s.avail_out != 0) { // truncated input
            inflateEnd(&s);
            return std::nullopt;
        }
    }
    inflateEnd(&s);
    out.resize(used);
    return out;
}

std::optional<std::string> gzip(std::string_view in) {
    z_stream s{};
    if (deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return std::nullopt;
    s.next_in  = reinterpret_cast<Bytef *>(const_cast<char *>(in.data()));
    s.avail_in = static_cast<uInt>(in.size());

    std::string out;
    size_t used = 0;
    for (;;) {
        if (out.size() - used < kZStep) out.resize(used + kZStep);
        s.next_out  = reinterpret_cast<Bytef *>(out.data() + used);
        s.avail_out = static_cast<uInt>(out.size() - used);
        const int rc = deflate(&s, Z_FINISH);
        used = out.size() - s.avail_out;
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK && rc != Z_BUF_ERROR) {
            deflateEnd(&s);
            return std::nullopt;
        }
        if (used > kZMaxOut) {
            deflateEnd(&s);
            return std::nullopt;
        }
    }
    deflateEnd(&s);
    out.resize(used);
    return out;
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

void splitHostPort(std::string_view hp, std::string &host, uint16_t &port) {
    host.clear();
    port = 0;
    hp = trimOws(hp);
    if (hp.empty()) return;

    if (hp.front() == '[') { // bracketed IPv6 literal
        const size_t rb = hp.find(']');
        if (rb == std::string_view::npos) {
            host.assign(hp.substr(1));
            return;
        }
        host.assign(hp.substr(1, rb - 1));
        std::string_view rest = hp.substr(rb + 1);
        if (rest.size() > 1 && rest.front() == ':') {
            size_t v = 0;
            if (parseDec(rest.substr(1), v) && v <= 65535) port = static_cast<uint16_t>(v);
        }
        return;
    }

    const size_t colon = hp.rfind(':');
    if (colon == std::string_view::npos || hp.find(':') != colon) {
        host.assign(hp); // no port, or a bare IPv6 literal
        return;
    }
    size_t v = 0;
    if (parseDec(hp.substr(colon + 1), v) && v <= 65535) {
        host.assign(hp.substr(0, colon));
        port = static_cast<uint16_t>(v);
    } else {
        host.assign(hp);
    }
}

Response blockedResponse(std::string_view contentTypeHint) {
    Response r;
    r.version = "HTTP/1.1";
    if (icontains(contentTypeHint, "image")) {
        r.status = 200;
        r.reason = "OK";
        r.body.assign(reinterpret_cast<const char *>(kGif), sizeof(kGif));
        r.headers.set("Content-Type", "image/gif");
        r.headers.set("Content-Length", std::to_string(r.body.size()));
    } else if (icontains(contentTypeHint, "javascript") || icontains(contentTypeHint, "script")) {
        r.status = 200;
        r.reason = "OK";
        r.headers.set("Content-Type", "application/javascript");
        r.headers.set("Content-Length", "0");
    } else {
        r.status = 204;
        r.reason = "No Content";
    }
    r.headers.set("Cache-Control", "no-store");
    r.headers.set("X-Adb-Blocked", "1");
    return r;
}

} // namespace adb::http
