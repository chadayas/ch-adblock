#include "adb/ca.hpp"
#include "adb/log.hpp"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace adb {
namespace {

// --------------------------------------------------------------------------
// Small RAII helpers. OpenSSL error paths are long and branchy; unique_ptr
// keeps them honest without a single explicit free in the happy path.
// --------------------------------------------------------------------------
template <class T, void (*F)(T *)> struct Deleter {
    void operator()(T *p) const noexcept {
        if (p) F(p);
    }
};
using BioPtr    = std::unique_ptr<BIO, Deleter<BIO, [](BIO *b) { BIO_free_all(b); }>>;
using X509Ptr   = std::unique_ptr<X509, Deleter<X509, X509_free>>;
using PkeyPtr   = std::unique_ptr<EVP_PKEY, Deleter<EVP_PKEY, EVP_PKEY_free>>;
using BnPtr     = std::unique_ptr<BIGNUM, Deleter<BIGNUM, BN_free>>;
using Asn1IntPtr = std::unique_ptr<ASN1_INTEGER, Deleter<ASN1_INTEGER, ASN1_INTEGER_free>>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Deleter<ASN1_TIME, ASN1_TIME_free>>;

// Top of the OpenSSL error stack as text; drains the rest so a later failure
// never reports a stale reason.
std::string sslErr() {
    unsigned long e = ERR_get_error();
    if (e == 0) return "no OpenSSL error queued";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return std::string(buf);
}

// 20 random bytes, top bit cleared so the DER INTEGER is positive. Matches
// what public CAs do and keeps every leaf distinct even for the same host.
bool setRandomSerial(X509 *cert) {
    unsigned char raw[20];
    if (RAND_bytes(raw, sizeof raw) != 1) {
        ADB_ERR("RAND_bytes failed: {}", sslErr());
        return false;
    }
    raw[0] &= 0x7F;
    if (raw[0] == 0) raw[0] = 1; // avoid a leading zero byte / zero serial
    BnPtr bn(BN_bin2bn(raw, (int)sizeof raw, nullptr));
    if (!bn) {
        ADB_ERR("BN_bin2bn failed: {}", sslErr());
        return false;
    }
    Asn1IntPtr serial(BN_to_ASN1_INTEGER(bn.get(), nullptr));
    if (!serial || X509_set_serialNumber(cert, serial.get()) != 1) {
        ADB_ERR("X509_set_serialNumber failed: {}", sslErr());
        return false;
    }
    return true;
}

bool addExt(X509 *cert, X509V3_CTX *ctx, int nid, const char *value) {
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, ctx, nid, value);
    if (!ex) {
        ADB_ERR("X509V3_EXT_conf_nid(nid={}, \"{}\") failed: {}", nid, value, sslErr());
        return false;
    }
    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    if (ok != 1) {
        ADB_ERR("X509_add_ext(nid={}) failed: {}", nid, sslErr());
        return false;
    }
    return true;
}

bool setName(X509_NAME *name, const char *field, const char *value) {
    if (X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(value), -1, -1,
                                   0) != 1) {
        ADB_ERR("X509_NAME_add_entry_by_txt({}) failed: {}", field, sslErr());
        return false;
    }
    return true;
}

// SAN needs "IP:1.2.3.4" for literals and "DNS:example.com" for names; a
// DNS-typed SAN carrying an address never matches in any client.
bool isIpLiteral(const std::string &host) {
    unsigned char buf[16];
    if (inet_pton(AF_INET, host.c_str(), buf) == 1) return true;
    return inet_pton(AF_INET6, host.c_str(), buf) == 1;
}

// Writes `write_pem(FILE*)` to `path` created with exactly `mode`. Creating
// the file with O_CREAT and the final mode closes the window where a fresh
// ca.key would sit world-readable.
template <class Fn>
bool writePem(const std::filesystem::path &path, mode_t mode, Fn &&write_pem) {
    ::unlink(path.c_str()); // drop a stale file rather than inherit its mode
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        ADB_ERR("cannot create {}: {}", path.string(), std::strerror(errno));
        return false;
    }
    FILE *fp = ::fdopen(fd, "w");
    if (!fp) {
        ADB_ERR("fdopen({}) failed: {}", path.string(), std::strerror(errno));
        ::close(fd);
        return false;
    }
    bool ok = write_pem(fp);
    if (std::fclose(fp) != 0) ok = false;
    if (!ok) {
        ADB_ERR("failed writing PEM to {}", path.string());
        ::unlink(path.c_str());
    }
    return ok;
}

constexpr long kHour       = 3600L;
constexpr long kCaLifetime = 10L * 365 * 24 * 3600; // ~10 years
constexpr long kLeafDays   = 825L * 24 * 3600;      // CA/Browser Forum ceiling

// Only http/1.1, in ALPN wire format. See notes/03 section 4: we deliberately
// never speak HTTP/2, so we must not let it be negotiated.
const unsigned char kAlpnHttp11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

int alpnSelectCb(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                 unsigned int inlen, void *) {
    unsigned char *sel = nullptr;
    if (SSL_select_next_proto(&sel, outlen, kAlpnHttp11, (unsigned int)sizeof kAlpnHttp11, in,
                              inlen) != OPENSSL_NPN_NEGOTIATED) {
        // The client offered no http/1.1. Decline the extension rather than
        // agreeing to something we cannot parse.
        return SSL_TLSEXT_ERR_NOACK;
    }
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
}

int sniCb(SSL *ssl, int *al, void *) {
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!name || !*name) return SSL_TLSEXT_ERR_NOACK; // no SNI: keep the ctx default

    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    auto *ca     = static_cast<CertAuthority *>(SSL_CTX_get_app_data(ctx));
    if (!ca) {
        ADB_ERR("no CertAuthority attached to SSL_CTX for '{}'", name);
        if (al) *al = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    CertAuthority::Leaf leaf = ca->leafFor(name);
    if (!leaf.cert || !leaf.key) {
        if (al) *al = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    if (SSL_use_certificate(ssl, leaf.cert) != 1 || SSL_use_PrivateKey(ssl, leaf.key) != 1) {
        ADB_ERR("cannot install leaf for '{}': {}", name, sslErr());
        if (al) *al = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    ADB_TRACE("SNI '{}' served with a minted leaf", name);
    return SSL_TLSEXT_ERR_OK;
}

} // namespace

// --------------------------------------------------------------------------
// One cached leaf. The X509 is owned outright; the key is a shared reference
// to CertAuthority::leafKey_, refcounted so an Entry is destructible in
// isolation and never leaves a dangling EVP_PKEY behind.
// --------------------------------------------------------------------------
struct CertAuthority::Entry {
    X509 *cert     = nullptr;
    EVP_PKEY *key  = nullptr;
    ~Entry() {
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
    }
};

CertAuthority::CertAuthority() = default;

CertAuthority::~CertAuthority() {
    cache_.clear();
    if (caCert_) X509_free(caCert_);
    if (caKey_) EVP_PKEY_free(caKey_);
    if (leafKey_) EVP_PKEY_free(leafKey_);
}

bool CertAuthority::ensure(const std::filesystem::path &dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec && !std::filesystem::is_directory(dir)) {
        ADB_ERR("cannot create {}: {}", dir.string(), ec.message());
        return false;
    }
    // 0700: the CA private key lives here.
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    if (ec) ADB_WARN("cannot chmod 0700 {}: {}", dir.string(), ec.message());

    caCrt_ = dir / "ca.crt";
    caKeyPath_ = dir / "ca.key";

    bool have = std::filesystem::exists(caCrt_) && std::filesystem::exists(caKeyPath_);
    if (have && loadCa()) {
        ADB_INFO("loaded CA from {}", caCrt_.string());
    } else {
        if (have) ADB_WARN("{} did not parse, regenerating", caCrt_.string());
        if (!generateCa()) return false;
        ADB_INFO("generated CA at {}", caCrt_.string());
    }

    // One EC key shared by every leaf certificate. Minting a fresh key per
    // host costs a few milliseconds of keygen on the connection's critical
    // path and buys nothing: the CA private key that signs all of them is
    // already sitting on the same disk, so an attacker who can read one key
    // can read them all. Reuse is the honest trade.
    if (!leafKey_) {
        leafKey_ = EVP_EC_gen("P-256");
        if (!leafKey_) {
            ADB_ERR("EVP_EC_gen(P-256) for the leaf key failed: {}", sslErr());
            return false;
        }
    }
    return true;
}

bool CertAuthority::loadCa() {
    X509Ptr cert;
    PkeyPtr key;

    if (FILE *fp = std::fopen(caCrt_.c_str(), "r")) {
        cert.reset(PEM_read_X509(fp, nullptr, nullptr, nullptr));
        std::fclose(fp);
    }
    if (!cert) {
        ADB_WARN("cannot read certificate {}: {}", caCrt_.string(), sslErr());
        return false;
    }
    if (FILE *fp = std::fopen(caKeyPath_.c_str(), "r")) {
        key.reset(PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr));
        std::fclose(fp);
    }
    if (!key) {
        ADB_WARN("cannot read private key {}: {}", caKeyPath_.string(), sslErr());
        return false;
    }
    if (X509_check_private_key(cert.get(), key.get()) != 1) {
        ADB_WARN("{} does not match {}: {}", caKeyPath_.string(), caCrt_.string(), sslErr());
        return false;
    }

    if (caCert_) X509_free(caCert_);
    if (caKey_) EVP_PKEY_free(caKey_);
    caCert_ = cert.release();
    caKey_  = key.release();
    return true;
}

bool CertAuthority::generateCa() {
    PkeyPtr key(EVP_EC_gen("P-256"));
    if (!key) {
        ADB_ERR("EVP_EC_gen(P-256) failed: {}", sslErr());
        return false;
    }
    X509Ptr cert(X509_new());
    if (!cert) {
        ADB_ERR("X509_new failed: {}", sslErr());
        return false;
    }
    if (X509_set_version(cert.get(), 2) != 1) { // 2 == X509v3
        ADB_ERR("X509_set_version failed: {}", sslErr());
        return false;
    }
    if (!setRandomSerial(cert.get())) return false;
    if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), -kHour) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), kCaLifetime)) {
        ADB_ERR("X509_gmtime_adj failed: {}", sslErr());
        return false;
    }

    X509_NAME *subject = X509_get_subject_name(cert.get());
    if (!setName(subject, "CN", "adb Local CA") || !setName(subject, "O", "adb")) return false;
    // Self-signed: issuer is the subject.
    if (X509_set_issuer_name(cert.get(), subject) != 1) {
        ADB_ERR("X509_set_issuer_name failed: {}", sslErr());
        return false;
    }
    if (X509_set_pubkey(cert.get(), key.get()) != 1) {
        ADB_ERR("X509_set_pubkey failed: {}", sslErr());
        return false;
    }

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    if (!addExt(cert.get(), &ctx, NID_basic_constraints, "critical,CA:TRUE,pathlen:0") ||
        !addExt(cert.get(), &ctx, NID_key_usage, "critical,keyCertSign,cRLSign") ||
        !addExt(cert.get(), &ctx, NID_subject_key_identifier, "hash"))
        return false;

    if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) {
        ADB_ERR("X509_sign failed: {}", sslErr());
        return false;
    }

    if (!writePem(caCrt_, 0644, [&](FILE *fp) { return PEM_write_X509(fp, cert.get()) == 1; }))
        return false;
    // Unencrypted: the proxy must come up without a passphrase prompt. 0600 in
    // a 0700 directory is the whole of the protection.
    if (!writePem(caKeyPath_, 0600, [&](FILE *fp) {
            return PEM_write_PrivateKey(fp, key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1;
        })) {
        std::error_code ec;
        std::filesystem::remove(caCrt_, ec);
        return false;
    }

    if (caCert_) X509_free(caCert_);
    if (caKey_) EVP_PKEY_free(caKey_);
    caCert_ = cert.release();
    caKey_  = key.release();
    return true;
}

std::string CertAuthority::caPem() const {
    std::lock_guard lk(mu_);
    if (!caCert_) return {};
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio || PEM_write_bio_X509(bio.get(), caCert_) != 1) {
        ADB_ERR("PEM_write_bio_X509 failed: {}", sslErr());
        return {};
    }
    char *data  = nullptr;
    long length = BIO_get_mem_data(bio.get(), &data);
    if (length <= 0 || !data) return {};
    return std::string(data, (size_t)length);
}

CertAuthority::Leaf CertAuthority::leafFor(std::string_view host) {
    std::string name(host);
    std::lock_guard lk(mu_);

    if (auto it = cache_.find(name); it != cache_.end())
        return Leaf{it->second->cert, it->second->key};

    if (!caCert_ || !caKey_ || !leafKey_) {
        ADB_ERR("leafFor('{}') before ensure() succeeded", name);
        return {};
    }

    X509Ptr cert(X509_new());
    if (!cert) {
        ADB_ERR("X509_new failed: {}", sslErr());
        return {};
    }
    if (X509_set_version(cert.get(), 2) != 1) {
        ADB_ERR("X509_set_version failed: {}", sslErr());
        return {};
    }
    if (!setRandomSerial(cert.get())) return {};

    if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), -kHour)) {
        ADB_ERR("X509_gmtime_adj(notBefore) failed: {}", sslErr());
        return {};
    }
    Asn1TimePtr not_after(ASN1_TIME_new());
    if (!not_after || !X509_time_adj_ex(not_after.get(), 0, kLeafDays, nullptr)) {
        ADB_ERR("X509_time_adj_ex failed: {}", sslErr());
        return {};
    }
    // A leaf outliving its issuer is worthless; clamp to the CA's notAfter.
    const ASN1_TIME *ca_end = X509_get0_notAfter(caCert_);
    if (ca_end && ASN1_TIME_compare(not_after.get(), ca_end) > 0) {
        if (X509_set1_notAfter(cert.get(), ca_end) != 1) {
            ADB_ERR("X509_set1_notAfter failed: {}", sslErr());
            return {};
        }
    } else if (X509_set1_notAfter(cert.get(), not_after.get()) != 1) {
        ADB_ERR("X509_set1_notAfter failed: {}", sslErr());
        return {};
    }

    X509_NAME *subject = X509_get_subject_name(cert.get());
    if (!setName(subject, "CN", name.c_str())) return {};
    if (X509_set_issuer_name(cert.get(), X509_get_subject_name(caCert_)) != 1) {
        ADB_ERR("X509_set_issuer_name failed: {}", sslErr());
        return {};
    }
    if (X509_set_pubkey(cert.get(), leafKey_) != 1) {
        ADB_ERR("X509_set_pubkey failed: {}", sslErr());
        return {};
    }

    std::string san = (isIpLiteral(name) ? "IP:" : "DNS:") + name;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, caCert_, cert.get(), nullptr, nullptr, 0);
    if (!addExt(cert.get(), &ctx, NID_subject_alt_name, san.c_str()) ||
        !addExt(cert.get(), &ctx, NID_basic_constraints, "critical,CA:FALSE") ||
        !addExt(cert.get(), &ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment") ||
        !addExt(cert.get(), &ctx, NID_ext_key_usage, "serverAuth") ||
        !addExt(cert.get(), &ctx, NID_authority_key_identifier, "keyid,issuer"))
        return {};

    if (X509_sign(cert.get(), caKey_, EVP_sha256()) == 0) {
        ADB_ERR("cannot sign leaf for '{}': {}", name, sslErr());
        return {};
    }

    // Cap the cache and, on overflow, drop it wholesale instead of running an
    // LRU. Minting is one ECDSA signature (tens of microseconds) so the reload
    // cost after a flush is negligible, and it keeps this map free of the
    // intrusive list an LRU would need. 2048 hosts is far more than any real
    // browsing session touches.
    if (cache_.size() >= 2048) {
        ADB_INFO("leaf cache hit {} entries, flushing", cache_.size());
        cache_.clear();
    }

    auto entry  = std::make_unique<Entry>();
    entry->cert = cert.release();
    // Non-owning in spirit -- it is leafKey_ -- but refcounted so ~Entry can
    // free it unconditionally and outliving order never matters.
    EVP_PKEY_up_ref(leafKey_);
    entry->key = leafKey_;

    Leaf out{entry->cert, entry->key};
    cache_.emplace(std::move(name), std::move(entry));
    return out;
}

// --------------------------------------------------------------------------
// TLS contexts
// --------------------------------------------------------------------------

SSL_CTX *makeServerCtx(CertAuthority &ca) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ADB_ERR("SSL_CTX_new(server) failed: {}", sslErr());
        return nullptr;
    }
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        ADB_ERR("SSL_CTX_set_min_proto_version failed: {}", sslErr());
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // TLS1.2 suites only; 1.3 suites are governed separately and OpenSSL's
    // defaults there are already the right ones.
    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES:!DSS") != 1) {
        ADB_ERR("SSL_CTX_set_cipher_list failed: {}", sslErr());
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    // The SNI callback reaches the CA back through here.
    SSL_CTX_set_app_data(ctx, &ca);
    SSL_CTX_set_tlsext_servername_callback(ctx, sniCb);
    SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCb, nullptr);
    return ctx;
}

SSL_CTX *makeClientCtx() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ADB_ERR("SSL_CTX_new(client) failed: {}", sslErr());
        return nullptr;
    }
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        ADB_ERR("SSL_CTX_set_min_proto_version failed: {}", sslErr());
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // Once we MITM, the browser can no longer see the true certificate: it
    // only ever sees one we minted. This verification is therefore the ONLY
    // thing standing between the user and a forged origin. Never relax it.
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        ADB_ERR("SSL_CTX_set_default_verify_paths failed: {}", sslErr());
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    // Advertise only http/1.1 upstream so the origin downgrades and we never
    // have to speak HTTP/2 (notes/03 section 4).
    if (SSL_CTX_set_alpn_protos(ctx, kAlpnHttp11, (unsigned int)sizeof kAlpnHttp11) != 0) {
        ADB_ERR("SSL_CTX_set_alpn_protos failed: {}", sslErr());
        SSL_CTX_free(ctx);
        return nullptr;
    }
    return ctx;
}

} // namespace adb
