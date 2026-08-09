#pragma once
#include <filesystem>
#include <memory>
#include <mutex>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <string>
#include <string_view>
#include <unordered_map>

namespace adb {

// ---------------------------------------------------------------------------
// A local certificate authority plus an on-the-fly leaf-certificate mint,
// mirroring AdGuard's CertificateManager (notes/03 section 2).
//
//   ensure()   - load CA from disk, generating it on first run
//   leafFor()  - return (and cache) a certificate for one SNI name
//
// Thread-safe. Leaf certs are cached in memory keyed by hostname.
// ---------------------------------------------------------------------------
class CertAuthority {
public:
    CertAuthority();
    ~CertAuthority();
    CertAuthority(const CertAuthority &) = delete;
    CertAuthority &operator=(const CertAuthority &) = delete;

    // Loads <dir>/ca.crt + <dir>/ca.key, creating a 10-year self-signed
    // root if either is missing. Returns false on unrecoverable error.
    bool ensure(const std::filesystem::path &dir);

    // PEM of the CA certificate, for the user to import into their trust store.
    std::string caPem() const;
    const std::filesystem::path &caPath() const { return caCrt_; }

    struct Leaf {
        X509 *cert = nullptr;    // owned by the cache, do not free
        EVP_PKEY *key = nullptr; // owned by the cache, do not free
    };

    // Mints (or returns cached) a leaf for `host`, with SAN = host.
    // Returns {nullptr,nullptr} on failure.
    Leaf leafFor(std::string_view host);

private:
    struct Entry;
    std::filesystem::path caCrt_, caKeyPath_;
    X509 *caCert_    = nullptr;
    EVP_PKEY *caKey_ = nullptr;
    EVP_PKEY *leafKey_ = nullptr; // one key reused by every leaf; cheap and fine
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::unique_ptr<Entry>> cache_;

    bool generateCa();
    bool loadCa();
};

// ---------------------------------------------------------------------------
// TLS contexts.
// ---------------------------------------------------------------------------

// Server-side context that answers the browser. Uses SNI to pick a leaf from
// `ca`. Advertises only http/1.1 in ALPN so we never have to speak HTTP/2.
SSL_CTX *makeServerCtx(CertAuthority &ca);

// Client-side context used for the real upstream connection. Verifies against
// the system trust store -- once we MITM, we own TLS security (notes/03 s2).
SSL_CTX *makeClientCtx();

} // namespace adb
