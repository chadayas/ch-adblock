#include "adb/proxy.hpp"

#include "adb/http.hpp"
#include "adb/log.hpp"
#include "adb/rule.hpp"
#include "adb/url.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace adb {
namespace {

constexpr int kMaxConns       = 512;
constexpr int kSockTimeoutSec = 60;
constexpr int kTunnelIdleMs   = 120 * 1000;
constexpr size_t kIoChunk     = 16 * 1024;
constexpr size_t kTunnelBuf   = 8 * 1024;
// Above this a non-rewritable body is relayed instead of buffered.
constexpr size_t kStreamAbove = 1u << 20;

constexpr char lowerc(char c) { return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c; }

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (lowerc(a[i]) != lowerc(b[i])) return false;
    return true;
}

size_t ifind(std::string_view hay, std::string_view needle, size_t from = 0) {
    if (needle.empty() || hay.size() < needle.size()) return std::string_view::npos;
    const size_t last = hay.size() - needle.size();
    for (size_t i = from; i <= last; ++i) {
        size_t j = 0;
        while (j < needle.size() && lowerc(hay[i + j]) == lowerc(needle[j])) ++j;
        if (j == needle.size()) return i;
    }
    return std::string_view::npos;
}

bool icontains(std::string_view hay, std::string_view needle) {
    return ifind(hay, needle) != std::string_view::npos;
}

bool istartsWith(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && iequals(s.substr(0, p.size()), p);
}

std::string_view trimOws(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
    return s.substr(b, e - b);
}

std::vector<std::string_view> splitTokens(std::string_view s) {
    std::vector<std::string_view> out;
    size_t p = 0;
    while (p <= s.size()) {
        const size_t c = s.find(',', p);
        std::string_view tok = trimOws(s.substr(p, c == std::string_view::npos ? c : c - p));
        if (!tok.empty()) out.push_back(tok);
        if (c == std::string_view::npos) break;
        p = c + 1;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

void setSockOpts(int fd) {
    timeval tv{kSockTimeoutSec, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

int dialTcp(const std::string &host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    const std::string svc = std::to_string(port);
    if (::getaddrinfo(host.c_str(), svc.c_str(), &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (addrinfo *a = res; a; a = a->ai_next) {
        fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        setSockOpts(fd);
        if (::connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    return fd;
}

bool writeAllFd(int fd, const char *p, size_t n) {
    while (n) {
        const ssize_t w = ::send(fd, p, n, 0);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return false;
        }
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Conn: the one abstraction that lets the request loop be written once.
// ---------------------------------------------------------------------------

struct Conn {
    virtual ~Conn() = default;
    virtual ssize_t read(void *p, size_t n)        = 0;
    virtual ssize_t write(const void *p, size_t n) = 0;
    virtual void close()                           = 0;

    bool writeAll(std::string_view s) {
        size_t off = 0;
        while (off < s.size()) {
            const ssize_t w = write(s.data() + off, s.size() - off);
            if (w <= 0) return false;
            off += static_cast<size_t>(w);
        }
        return true;
    }
};

struct FdConn final : Conn {
    int fd = -1;
    explicit FdConn(int f) : fd(f) {}
    ~FdConn() override { close(); }

    ssize_t read(void *p, size_t n) override {
        for (;;) {
            const ssize_t r = ::recv(fd, p, n, 0);
            if (r < 0 && errno == EINTR) continue;
            return r;
        }
    }
    ssize_t write(const void *p, size_t n) override {
        for (;;) {
            const ssize_t w = ::send(fd, p, n, 0);
            if (w < 0 && errno == EINTR) continue;
            return w;
        }
    }
    void close() override {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }
};

struct SslConn final : Conn {
    SSL *ssl = nullptr;
    int fd   = -1;
    SslConn(SSL *s, int f) : ssl(s), fd(f) {}
    ~SslConn() override { close(); }

    ssize_t read(void *p, size_t n) override {
        const int r = SSL_read(ssl, p, static_cast<int>(n));
        return r > 0 ? r : (SSL_get_error(ssl, r) == SSL_ERROR_ZERO_RETURN ? 0 : -1);
    }
    ssize_t write(const void *p, size_t n) override {
        const int w = SSL_write(ssl, p, static_cast<int>(n));
        return w > 0 ? w : -1;
    }
    void close() override {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }
};

// ---------------------------------------------------------------------------
// Buffered reader over a Conn
// ---------------------------------------------------------------------------

struct Reader {
    Conn *c = nullptr;
    std::string buf;
    size_t pos = 0;
    bool eof   = false;

    std::string_view avail() const { return std::string_view(buf).substr(pos); }

    void consume(size_t n) {
        pos += n;
        if (pos >= buf.size()) {
            buf.clear();
            pos = 0;
        }
    }

    bool fill() {
        if (eof || !c) return false;
        if (pos > 0) {
            buf.erase(0, pos);
            pos = 0;
        }
        const size_t at = buf.size();
        buf.resize(at + kIoChunk);
        const ssize_t n = c->read(buf.data() + at, kIoChunk);
        buf.resize(at + (n > 0 ? static_cast<size_t>(n) : 0));
        if (n <= 0) {
            eof = true;
            return false;
        }
        return true;
    }
};

// 1 = parsed, 0 = clean EOF before any bytes, -1 = malformed / truncated
template <class M> int readHead(Reader &r, M &m, long (*parse)(std::string_view, M &)) {
    for (;;) {
        if (!r.avail().empty()) {
            const long n = parse(r.avail(), m);
            if (n > 0) {
                r.consume(static_cast<size_t>(n));
                return 1;
            }
            if (n < 0) return -1;
        }
        if (!r.fill()) return r.avail().empty() ? 0 : -1;
    }
}

bool readBody(Reader &r, const http::BodyPlan &plan, std::string &out) {
    out.clear();
    switch (plan.kind) {
    case http::BodyPlan::Kind::None:
        return true;
    case http::BodyPlan::Kind::Length:
        while (r.avail().size() < plan.length)
            if (!r.fill()) return false;
        out.assign(r.avail().substr(0, plan.length));
        r.consume(plan.length);
        return true;
    case http::BodyPlan::Kind::Chunked:
        for (;;) {
            size_t consumed = 0;
            if (auto b = http::dechunk(r.avail(), consumed)) {
                out = std::move(*b);
                r.consume(consumed);
                return true;
            }
            if (!r.fill()) return false;
        }
    case http::BodyPlan::Kind::UntilClose:
        while (r.fill()) {}
        out.assign(r.avail());
        r.consume(out.size());
        return true;
    }
    return false;
}

// Relays exactly `n` bytes from reader to conn without buffering them whole.
bool relayN(Reader &r, Conn &dst, size_t n) {
    while (n) {
        if (r.avail().empty() && !r.fill()) return false;
        const std::string_view a = r.avail();
        const size_t take = a.size() < n ? a.size() : n;
        if (!dst.writeAll(a.substr(0, take))) return false;
        r.consume(take);
        n -= take;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Header surgery
// ---------------------------------------------------------------------------

const char *const kHopByHop[] = {"Connection", "Proxy-Connection",   "Keep-Alive",
                                 "TE",         "Trailer",            "Transfer-Encoding",
                                 "Upgrade",    "Proxy-Authenticate", "Proxy-Authorization"};

void stripHopByHop(http::Headers &h, std::string_view connectionValue) {
    for (std::string_view tok : splitTokens(connectionValue)) {
        bool builtin = false;
        for (const char *n : kHopByHop) builtin = builtin || iequals(tok, n);
        if (!builtin) h.remove(tok);
    }
    for (const char *n : kHopByHop) h.remove(n);
}

// Drops encodings we cannot decode; leaves the rest alone.
void sanitizeAcceptEncoding(http::Headers &h) {
    const std::string_view ae = h.get("Accept-Encoding");
    if (ae.empty()) return;
    std::string kept;
    for (std::string_view tok : splitTokens(ae)) {
        const size_t semi = tok.find(';');
        const std::string_view name = trimOws(semi == std::string_view::npos ? tok : tok.substr(0, semi));
        if (iequals(name, "br") || iequals(name, "zstd")) continue;
        if (!kept.empty()) kept += ", ";
        kept.append(tok);
    }
    h.set("Accept-Encoding", kept.empty() ? "gzip" : kept);
}

std::string_view ctypeName(ContentType t) {
    switch (t) {
    case CT_Document:       return "document";
    case CT_Subdocument:    return "subdocument";
    case CT_Script:         return "script";
    case CT_Stylesheet:     return "stylesheet";
    case CT_Image:          return "image";
    case CT_Font:           return "font";
    case CT_Media:          return "media";
    case CT_XmlHttpRequest: return "xhr";
    case CT_WebSocket:      return "websocket";
    case CT_Ping:           return "ping";
    case CT_Popup:          return "popup";
    default:                return "other";
    }
}

void spliceCss(std::string &html, std::string_view css) {
    std::string tag;
    tag.reserve(css.size() + 16);
    tag += "<style>";
    tag.append(css);
    tag += "</style>";

    const size_t head = ifind(html, "<head");
    if (head != std::string::npos) {
        const size_t gt = html.find('>', head);
        if (gt != std::string::npos) {
            html.insert(gt + 1, tag);
            return;
        }
    }
    const size_t body = ifind(html, "<body");
    if (body != std::string::npos) {
        html.insert(body, tag);
        return;
    }
    html.insert(0, tag);
}

// ---------------------------------------------------------------------------
// Blind byte tunnel (pinned certificates / mTLS -- notes/03 s2)
// ---------------------------------------------------------------------------

void tunnel(int a, int b) {
    char buf[kTunnelBuf];
    pollfd fds[2];
    fds[0] = {a, POLLIN, 0};
    fds[1] = {b, POLLIN, 0};
    for (;;) {
        const int rc = ::poll(fds, 2, kTunnelIdleMs);
        if (rc == 0) return; // idle
        if (rc < 0) {
            if (errno == EINTR) continue;
            return;
        }
        for (int i = 0; i < 2; ++i) {
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            const int from = fds[i].fd, to = fds[1 - i].fd;
            const ssize_t n = ::recv(from, buf, sizeof buf, 0);
            if (n <= 0) return;
            if (!writeAllFd(to, buf, static_cast<size_t>(n))) return;
        }
        fds[0].revents = fds[1].revents = 0;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Impl
// ---------------------------------------------------------------------------

struct ProxyServer::Impl {
    ProxyConfig cfg;
    Engine &engine;
    CertAuthority &ca;
    ProxyStats &stats;

    std::atomic<bool> running{false};
    std::atomic<int> listenFd{-1};
    std::atomic<int> live{0};

    SSL_CTX *srvCtx = nullptr;
    SSL_CTX *cliCtx = nullptr;

    std::mutex noMitmMu;
    std::unordered_set<std::string> noMitm; // hosts that refused interception

    Impl(const ProxyConfig &c, Engine &e, CertAuthority &a, ProxyStats &s)
        : cfg(c), engine(e), ca(a), stats(s) {}

    bool skipMitm(const std::string &host) {
        std::lock_guard lk(noMitmMu);
        return noMitm.count(host) != 0;
    }
    void markNoMitm(const std::string &host) {
        std::lock_guard lk(noMitmMu);
        noMitm.insert(host);
    }

    // -----------------------------------------------------------------
    // One HTTP request/response exchange, shared by the TLS and the
    // cleartext path. Returns false when the client connection must close.
    // -----------------------------------------------------------------
    bool serveOne(Conn &client, Reader &cr, bool https, const std::string &fixedHost,
                  uint16_t fixedPort, http::Request *pending, std::unique_ptr<Conn> &oconn,
                  Reader &orr, std::string &ohost, uint16_t &oport);

    void requestLoop(Conn &client, Reader &cr, bool https, const std::string &fixedHost,
                     uint16_t fixedPort, http::Request *first, std::unique_ptr<Conn> origin);

    std::unique_ptr<Conn> dialOrigin(const std::string &host, uint16_t port, bool tls);
    void handleConnect(int cfd, Conn &client, Reader &cr, const http::Request &req);
    void handleClient(int cfd);
};

std::unique_ptr<Conn> ProxyServer::Impl::dialOrigin(const std::string &host, uint16_t port,
                                                    bool tls) {
    const int fd = dialTcp(host, port);
    if (fd < 0) return nullptr;
    if (!tls) return std::make_unique<FdConn>(fd);
    if (!cliCtx) {
        ::close(fd);
        return nullptr;
    }
    SSL *ssl = SSL_new(cliCtx);
    if (!ssl) {
        ::close(fd);
        return nullptr;
    }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set1_host(ssl, host.c_str());
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        ::close(fd);
        return nullptr;
    }
    return std::make_unique<SslConn>(ssl, fd);
}

bool ProxyServer::Impl::serveOne(Conn &client, Reader &cr, bool https,
                                 const std::string &fixedHost, uint16_t fixedPort,
                                 http::Request *pending, std::unique_ptr<Conn> &oconn, Reader &orr,
                                 std::string &ohost, uint16_t &oport) {
    // ---- 1. request head ----------------------------------------------
    http::Request req;
    if (pending) {
        req = std::move(*pending);
    } else {
        const int rc = readHead(cr, req, http::parseRequestHead);
        if (rc <= 0) return false;
    }
    stats.requests.fetch_add(1, std::memory_order_relaxed);

    const std::string clientConn(req.headers.get("Connection"));
    bool clientClose = icontains(clientConn, "close") ||
                       (req.version == "HTTP/1.0" && !icontains(clientConn, "keep-alive"));

    const http::BodyPlan reqPlan = http::planRequestBody(req);
    if (!readBody(cr, reqPlan, req.body)) return false;

    // ---- host / target -------------------------------------------------
    std::string host   = fixedHost;
    uint16_t port      = fixedPort;
    std::string scheme = https ? "https" : "http";

    if (!https) {
        if (istartsWith(req.target, "http://") || istartsWith(req.target, "https://")) {
            const url::Parts p = url::split(req.target);
            if (!p.valid) {
                client.writeAll("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                                "Connection: close\r\n\r\n");
                return false;
            }
            scheme = std::string(p.scheme);
            host   = url::lower(p.host);
            port   = p.port ? p.port : (iequals(scheme, "https") ? 443 : 80);
            std::string t(p.path.empty() ? std::string_view("/") : p.path);
            if (!p.query.empty()) {
                t += '?';
                t.append(p.query);
            }
            req.target = std::move(t);
        } else {
            std::string h;
            uint16_t hp = 0;
            http::splitHostPort(req.headers.get("Host"), h, hp);
            if (h.empty()) {
                client.writeAll("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                                "Connection: close\r\n\r\n");
                return false;
            }
            host = url::lower(h);
            port = hp ? hp : 80;
        }
    }
    if (host.empty()) return false;

    const size_t q = req.target.find('?');
    const std::string_view path =
        std::string_view(req.target).substr(0, q == std::string::npos ? req.target.size() : q);

    std::string absUrl;
    absUrl.reserve(scheme.size() + host.size() + req.target.size() + 4);
    absUrl += scheme;
    absUrl += "://";
    absUrl += host;
    absUrl += req.target;

    // ---- 2. document host for third-party ------------------------------
    std::string docHost;
    const std::string_view referer = req.headers.get("Referer");
    if (!referer.empty()) {
        const url::Parts rp = url::split(referer);
        if (rp.valid) docHost = url::lower(rp.host);
    }
    if (docHost.empty() && iequals(req.headers.get("Sec-Fetch-Site"), "same-origin"))
        docHost = host;

    // ---- 3/4. classify and match ---------------------------------------
    const std::string_view accept = req.headers.get("Accept");
    const ContentType ctype =
        guessContentType(req.headers.get("Sec-Fetch-Dest"), accept, path);
    const Method method = methodFromString(req.method);
    const adb::Request mreq = adb::Request::make(absUrl, docHost, ctype, method);
    const MatchResult mr    = engine.match(mreq);

    if (mr.blocked && mr.rule) {
        stats.blocked.fetch_add(1, std::memory_order_relaxed);
        ADB_INFO("BLOCK {} [{}] by {}", absUrl, ctypeName(ctype), mr.rule->text);
        http::Response br = http::blockedResponse(accept);
        br.headers.set("Connection", clientClose ? "close" : "keep-alive");
        if (!client.writeAll(br.serialize())) return false;
        return !clientClose;
    }

    // ---- 5. rewrite the request for the origin --------------------------
    stripHopByHop(req.headers, clientConn);
    req.headers.set("Connection", "keep-alive");
    {
        std::string hostHdr = host;
        if (port && port != (iequals(scheme, "https") ? 443 : 80)) {
            hostHdr += ':';
            hostHdr += std::to_string(port);
        }
        req.headers.set("Host", hostHdr);
    }
    const bool isDoc = (ctype & (CT_Document | CT_Subdocument)) != 0;
    if (cfg.injectCss && isDoc)
        req.headers.set("Accept-Encoding", "gzip");
    else
        sanitizeAcceptEncoding(req.headers);

    if (cfg.stealthHeaders) {
        req.headers.set("DNT", "1");
        req.headers.set("Sec-GPC", "1");
        req.headers.remove("X-Client-Data");
        req.headers.remove("If-None-Match");
    }
    if (reqPlan.kind != http::BodyPlan::Kind::None)
        req.headers.set("Content-Length", std::to_string(req.body.size()));

    // ---- 6. talk to the origin ------------------------------------------
    const std::string wire = req.serialize();
    http::Response resp;
    bool got = false;

    for (int attempt = 0; attempt < 2 && !got; ++attempt) {
        const bool fresh = !oconn || ohost != host || oport != port || orr.eof;
        if (fresh) {
            oconn = dialOrigin(host, port, iequals(scheme, "https"));
            if (!oconn) {
                ADB_WARN("upstream connect failed: {}:{}", host, port);
                client.writeAll("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                                "Connection: close\r\n\r\n");
                return false;
            }
            ohost = host;
            oport = port;
            orr   = Reader{};
            orr.c = oconn.get();
        }
        if (!oconn->writeAll(wire) || readHead(orr, resp, http::parseResponseHead) != 1) {
            oconn.reset();
            orr = Reader{};
            continue; // stale keep-alive socket: redial once
        }
        got = true;
    }
    if (!got) {
        client.writeAll("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                        "Connection: close\r\n\r\n");
        return false;
    }

    // 1xx interim responses: pass through and read the real one.
    while (resp.status >= 100 && resp.status < 200) {
        if (!client.writeAll(resp.serialize())) return false;
        if (readHead(orr, resp, http::parseResponseHead) != 1) return false;
    }

    const http::BodyPlan rplan = http::planResponseBody(resp, req.method);
    const std::string respConn(resp.headers.get("Connection"));
    bool originClose = icontains(respConn, "close") ||
                       rplan.kind == http::BodyPlan::Kind::UntilClose ||
                       (resp.version == "HTTP/1.0" && !icontains(respConn, "keep-alive"));

    // ---- 7. rewrite the response ----------------------------------------
    stripHopByHop(resp.headers, respConn);
    if (cfg.blockQuicHint) resp.headers.remove("Alt-Svc");
    if (cfg.stealthHeaders) resp.headers.remove("ETag");

    const std::string_view ctypeHdr = resp.headers.get("Content-Type");
    const bool htmlish = cfg.injectCss && istartsWith(trimOws(ctypeHdr), "text/html");
    const bool rewritable =
        htmlish && (rplan.kind != http::BodyPlan::Kind::Length || rplan.length <= cfg.maxRewriteBody);

    // Large opaque bodies stream straight through instead of being buffered.
    if (!rewritable && rplan.kind == http::BodyPlan::Kind::Length &&
        rplan.length > kStreamAbove) {
        resp.headers.set("Content-Length", std::to_string(rplan.length));
        resp.version = "HTTP/1.1";
        resp.headers.set("Connection", clientClose ? "close" : "keep-alive");
        std::string head = resp.serialize(); // body is empty here
        if (!client.writeAll(head)) return false;
        if (!relayN(orr, client, rplan.length)) return false;
        if (originClose) {
            oconn.reset();
            orr = Reader{};
        }
        return !clientClose;
    }

    if (!readBody(orr, rplan, resp.body)) {
        if (rplan.kind != http::BodyPlan::Kind::UntilClose) return false;
    }

    if (rewritable && resp.body.size() <= cfg.maxRewriteBody) {
        const std::string_view enc = trimOws(resp.headers.get("Content-Encoding"));
        const bool identity = enc.empty() || iequals(enc, "identity");
        const bool zlibbed =
            iequals(enc, "gzip") || iequals(enc, "x-gzip") || iequals(enc, "deflate");
        if (identity || zlibbed) {
            const std::string css = engine.cosmeticCss(host);
            if (!css.empty()) {
                bool ok = true;
                std::string plain;
                if (identity) {
                    plain = std::move(resp.body);
                } else if (auto g = http::gunzip(resp.body)) {
                    plain = std::move(*g);
                } else {
                    ok = false;
                }
                if (ok) {
                    spliceCss(plain, css);
                    resp.body = std::move(plain);
                    resp.headers.remove("Content-Encoding");
                    stats.cssInjected.fetch_add(1, std::memory_order_relaxed);
                    ADB_DBG("injected {} bytes of CSS into {}", css.size(), host);
                }
            }
        }
    }

    // The body is now identity-framed no matter how it arrived.
    resp.headers.remove("Transfer-Encoding");
    if (rplan.kind != http::BodyPlan::Kind::None)
        resp.headers.set("Content-Length", std::to_string(resp.body.size()));
    resp.version = "HTTP/1.1"; // we re-framed the body, so we own the framing
    resp.headers.set("Connection", clientClose ? "close" : "keep-alive");

    // ---- 8. answer the client -------------------------------------------
    if (!client.writeAll(resp.serialize())) return false;
    if (originClose) {
        oconn.reset();
        orr = Reader{};
    }
    return !clientClose;
}

void ProxyServer::Impl::requestLoop(Conn &client, Reader &cr, bool https,
                                    const std::string &fixedHost, uint16_t fixedPort,
                                    http::Request *first, std::unique_ptr<Conn> origin) {
    std::unique_ptr<Conn> oconn = std::move(origin);
    Reader orr;
    orr.c = oconn ? oconn.get() : nullptr;
    std::string ohost = oconn ? fixedHost : std::string();
    uint16_t oport    = oconn ? fixedPort : 0;

    http::Request *pending = first;
    while (running.load(std::memory_order_relaxed)) {
        if (!serveOne(client, cr, https, fixedHost, fixedPort, pending, oconn, orr, ohost, oport))
            break;
        pending = nullptr;
    }
}

void ProxyServer::Impl::handleConnect(int cfd, Conn &client, Reader &cr,
                                      const http::Request &req) {
    std::string host;
    uint16_t port = 0;
    http::splitHostPort(req.target, host, port);
    if (host.empty()) {
        client.writeAll("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    if (!port) port = 443;
    host = url::lower(host);

    // a. origin TCP first, so a failure is still reportable as 502.
    int ofd = dialTcp(host, port);
    if (ofd < 0) {
        ADB_WARN("CONNECT {}:{} failed", host, port);
        client.writeAll("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    if (!client.writeAll("HTTP/1.1 200 Connection Established\r\n\r\n")) {
        ::close(ofd);
        return;
    }

    const bool knownPinned = skipMitm(host);
    SSL *ussl = nullptr;
    if (!knownPinned && cliCtx && srvCtx) {
        ussl = SSL_new(cliCtx);
        if (ussl) {
            SSL_set_fd(ussl, ofd);
            SSL_set_tlsext_host_name(ussl, host.c_str());
            SSL_set1_host(ussl, host.c_str());
            if (SSL_connect(ussl) != 1) {
                SSL_free(ussl);
                ussl = nullptr;
            }
        }
    }

    // b. upstream handshake failed (pinning, mTLS, ESNI, ...) -> blind tunnel.
    if (!ussl) {
        ::close(ofd);
        ofd = dialTcp(host, port);
        if (ofd < 0) return;
        if (!knownPinned) {
            markNoMitm(host);
            ADB_INFO("passthrough tunnel for {} (upstream handshake refused)", host);
        }
        stats.tunneled.fetch_add(1, std::memory_order_relaxed);
        tunnel(cfd, ofd);
        ::close(ofd);
        return;
    }

    // c. client-side handshake with a minted leaf.
    SSL *cssl = SSL_new(srvCtx);
    if (!cssl) {
        SSL_shutdown(ussl);
        SSL_free(ussl);
        ::close(ofd);
        return;
    }
    SSL_set_fd(cssl, cfd);
    if (SSL_accept(cssl) != 1) {
        ADB_DBG("client handshake failed for {}", host);
        SSL_free(cssl);
        SSL_shutdown(ussl);
        SSL_free(ussl);
        ::close(ofd);
        return;
    }

    // d. plaintext both ways.
    auto originConn = std::make_unique<SslConn>(ussl, ofd);
    SslConn clientTls(cssl, cfd);
    Reader tcr;
    tcr.c = &clientTls;
    requestLoop(clientTls, tcr, true, host, port, nullptr, std::move(originConn));
    clientTls.fd = -1; // the FdConn wrapper in handleClient owns cfd
}

void ProxyServer::Impl::handleClient(int cfd) {
    setSockOpts(cfd);
    FdConn client(cfd);
    Reader cr;
    cr.c = &client;

    http::Request req;
    if (readHead(cr, req, http::parseRequestHead) != 1) {
        client.writeAll("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return;
    }

    if (iequals(req.method, "CONNECT")) {
        handleConnect(cfd, client, cr, req);
        return;
    }
    if (istartsWith(req.target, "http://") || istartsWith(req.target, "https://")) {
        requestLoop(client, cr, false, std::string(), 0, &req, nullptr);
        return;
    }
    ADB_DBG("rejecting non-proxy request: {} {}", req.method, req.target);
    client.writeAll("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                    "Connection: close\r\n\r\n");
}

// ---------------------------------------------------------------------------
// ProxyServer
// ---------------------------------------------------------------------------

ProxyServer::ProxyServer(const ProxyConfig &cfg, Engine &engine, CertAuthority &ca)
    : impl_(std::make_unique<Impl>(cfg, engine, ca, stats_)) {
    ::signal(SIGPIPE, SIG_IGN);
}

ProxyServer::~ProxyServer() {
    stop();
    // Give detached workers a moment to unwind before Impl disappears.
    for (int i = 0; i < 200 && impl_->live.load() > 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (impl_->srvCtx) SSL_CTX_free(impl_->srvCtx);
    if (impl_->cliCtx) SSL_CTX_free(impl_->cliCtx);
}

bool ProxyServer::run() {
    Impl &p = *impl_;

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;
    addrinfo *res     = nullptr;
    const std::string svc = std::to_string(p.cfg.listenPort);
    const char *node = p.cfg.listenAddr.empty() ? nullptr : p.cfg.listenAddr.c_str();
    if (::getaddrinfo(node, svc.c_str(), &hints, &res) != 0 || !res) {
        ADB_ERR("cannot resolve listen address {}", p.cfg.listenAddr);
        return false;
    }

    int lfd = -1;
    for (addrinfo *a = res; a; a = a->ai_next) {
        lfd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (lfd < 0) continue;
        int one = 1;
        ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (::bind(lfd, a->ai_addr, a->ai_addrlen) == 0 && ::listen(lfd, 128) == 0) break;
        ::close(lfd);
        lfd = -1;
    }
    ::freeaddrinfo(res);
    if (lfd < 0) {
        ADB_ERR("cannot listen on {}:{}: {}", p.cfg.listenAddr, p.cfg.listenPort,
                std::strerror(errno));
        return false;
    }

    p.srvCtx = makeServerCtx(p.ca);
    p.cliCtx = makeClientCtx();
    if (!p.srvCtx || !p.cliCtx)
        ADB_WARN("TLS contexts unavailable; HTTPS will be tunnelled unfiltered");

    p.listenFd.store(lfd);
    p.running.store(true);
    ADB_INFO("listening on {}:{}", p.cfg.listenAddr, p.cfg.listenPort);

    while (p.running.load()) {
        sockaddr_storage ss{};
        socklen_t sl = sizeof ss;
        const int cfd = ::accept(lfd, reinterpret_cast<sockaddr *>(&ss), &sl);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (!p.running.load()) {
            ::close(cfd);
            break;
        }
        if (p.live.load() >= kMaxConns) {
            ADB_WARN("connection limit reached, rejecting");
            ::close(cfd);
            continue;
        }
        p.live.fetch_add(1);
        stats_.connections.fetch_add(1, std::memory_order_relaxed);
        std::thread([&p, cfd] {
            p.handleClient(cfd);
            p.live.fetch_sub(1);
        }).detach();
    }

    p.running.store(false);
    p.listenFd.store(-1);
    ::close(lfd);
    return true;
}

void ProxyServer::stop() {
    Impl &p = *impl_;
    if (!p.running.exchange(false)) return;
    const int lfd = p.listenFd.load();
    if (lfd >= 0) ::shutdown(lfd, SHUT_RDWR);
}

} // namespace adb
