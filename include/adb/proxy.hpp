#pragma once
#include "adb/ca.hpp"
#include "adb/engine.hpp"
#include <atomic>
#include <cstdint>
#include <string>

namespace adb {

struct ProxyConfig {
    std::string listenAddr = "127.0.0.1";
    uint16_t listenPort    = 8080;
    bool injectCss         = true;  // cosmetic element hiding
    bool stealthHeaders    = true;  // DNT / Sec-GPC / strip ETag & X-Client-Data
    bool blockQuicHint     = true;  // strip Alt-Svc so browsers stay on TCP
    size_t maxRewriteBody  = 8u << 20; // only rewrite HTML smaller than this
};

struct ProxyStats {
    std::atomic<uint64_t> connections{0};
    std::atomic<uint64_t> requests{0};
    std::atomic<uint64_t> blocked{0};
    std::atomic<uint64_t> cssInjected{0};
    std::atomic<uint64_t> tunneled{0}; // passthrough (pinned / handshake failed)
};

// Blocking, thread-per-connection HTTPS-intercepting proxy.
// Deliberately not an event loop: for a single user this is simpler and fast
// enough, and it keeps the interesting code (the engine) readable.
class ProxyServer {
public:
    ProxyServer(const ProxyConfig &cfg, Engine &engine, CertAuthority &ca);
    ~ProxyServer();

    // Binds and starts accepting. Blocks until stop() is called.
    // Returns false if the listen socket could not be created.
    bool run();
    void stop();

    const ProxyStats &stats() const { return stats_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    ProxyStats stats_;
};

} // namespace adb
