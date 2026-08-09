#include "adb/ca.hpp"
#include "harness.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <unistd.h>
#include <filesystem>
#include <string>

namespace {

namespace fs = std::filesystem;

// A temp dir that removes itself, so a failing CHECK never leaves a stray CA
// (and its private key) behind in /tmp.
struct TempDir {
    fs::path path;
    explicit TempDir(const char *tag) {
        path = fs::temp_directory_path() /
               ("adb_ca_test_" + std::string(tag) + "_" + std::to_string(::getpid()));
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

// Parses a PEM certificate out of a string; nullptr on failure.
X509 *certFromPem(const std::string &pem) {
    BIO *bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (!bio) return nullptr;
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

std::string subjectCn(X509 *cert) {
    char buf[256] = {0};
    int n = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, buf, sizeof buf);
    return n > 0 ? std::string(buf, (size_t)n) : std::string();
}

// Every SAN entry rendered as "DNS:x" / "IP:x", joined by ','.
std::string sanText(X509 *cert) {
    auto *names = static_cast<GENERAL_NAMES *>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (!names) return {};
    std::string out;
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        const GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);
        if (gn->type != GEN_DNS && gn->type != GEN_IPADD) continue;
        if (!out.empty()) out += ',';
        if (gn->type == GEN_DNS) {
            const unsigned char *s = ASN1_STRING_get0_data(gn->d.dNSName);
            out += "DNS:";
            out += std::string(reinterpret_cast<const char *>(s),
                               (size_t)ASN1_STRING_length(gn->d.dNSName));
        } else {
            char ip[64] = {0};
            const unsigned char *raw = ASN1_STRING_get0_data(gn->d.iPAddress);
            int len                  = ASN1_STRING_length(gn->d.iPAddress);
            out += "IP:";
            if (len == 4)
                std::snprintf(ip, sizeof ip, "%u.%u.%u.%u", raw[0], raw[1], raw[2], raw[3]);
            out += ip;
        }
    }
    GENERAL_NAMES_free(names);
    return out;
}

} // namespace

TEST(ca_ensure_creates_and_reloads) {
    TempDir tmp("reload");

    adb::CertAuthority ca;
    CHECK(ca.ensure(tmp.path));
    CHECK(fs::exists(tmp.path / "ca.crt"));
    CHECK(fs::exists(tmp.path / "ca.key"));
    CHECK_EQ(ca.caPath().string(), (tmp.path / "ca.crt").string());

    std::string pem = ca.caPem();
    CHECK(pem.rfind("-----BEGIN CERTIFICATE-----", 0) == 0);

    // A second CA pointed at the same dir must load, not regenerate.
    adb::CertAuthority again;
    CHECK(again.ensure(tmp.path));
    CHECK_EQ(again.caPem(), pem);
}

TEST(ca_regenerates_over_garbage) {
    TempDir tmp("garbage");
    {
        std::FILE *f = std::fopen((tmp.path / "ca.crt").c_str(), "w");
        CHECK(f != nullptr);
        std::fputs("not a certificate\n", f);
        std::fclose(f);
        f = std::fopen((tmp.path / "ca.key").c_str(), "w");
        CHECK(f != nullptr);
        std::fputs("not a key\n", f);
        std::fclose(f);
    }
    adb::CertAuthority ca;
    CHECK(ca.ensure(tmp.path));
    CHECK(ca.caPem().rfind("-----BEGIN CERTIFICATE-----", 0) == 0);
}

TEST(ca_leaf_for_host) {
    TempDir tmp("leaf");
    adb::CertAuthority ca;
    CHECK(ca.ensure(tmp.path));

    adb::CertAuthority::Leaf leaf = ca.leafFor("www.learncpp.com");
    CHECK(leaf.cert != nullptr);
    CHECK(leaf.key != nullptr);
    if (!leaf.cert || !leaf.key) return;

    CHECK_EQ(subjectCn(leaf.cert), std::string("www.learncpp.com"));
    CHECK(sanText(leaf.cert).find("www.learncpp.com") != std::string::npos);

    // The leaf must actually chain to our CA.
    X509 *ca_cert = certFromPem(ca.caPem());
    CHECK(ca_cert != nullptr);
    if (ca_cert) {
        EVP_PKEY *ca_pub = X509_get_pubkey(ca_cert);
        CHECK(ca_pub != nullptr);
        CHECK_EQ(X509_verify(leaf.cert, ca_pub), 1);
        // Issuer of the leaf == subject of the CA.
        CHECK_EQ(X509_NAME_cmp(X509_get_issuer_name(leaf.cert), X509_get_subject_name(ca_cert)), 0);
        EVP_PKEY_free(ca_pub);
        X509_free(ca_cert);
    }

    // Not a CA, and usable as a TLS server cert.
    CHECK_EQ(X509_check_ca(leaf.cert), 0);
    CHECK_EQ(X509_check_host(leaf.cert, "www.learncpp.com", 0, 0, nullptr), 1);

    // Second call is a cache hit: same object, not a fresh mint.
    adb::CertAuthority::Leaf again = ca.leafFor("www.learncpp.com");
    CHECK(again.cert == leaf.cert);
    CHECK(again.key == leaf.key);

    // A different host gets a different certificate off the shared key.
    adb::CertAuthority::Leaf other = ca.leafFor("example.org");
    CHECK(other.cert != nullptr);
    CHECK(other.cert != leaf.cert);
    CHECK(other.key == leaf.key); // one EC key reused by every leaf
    if (other.cert) CHECK_EQ(subjectCn(other.cert), std::string("example.org"));
}

TEST(ca_leaf_for_ip_literal) {
    TempDir tmp("ip");
    adb::CertAuthority ca;
    CHECK(ca.ensure(tmp.path));

    adb::CertAuthority::Leaf leaf = ca.leafFor("192.0.2.7");
    CHECK(leaf.cert != nullptr);
    if (!leaf.cert) return;
    // An address must land in an iPAddress SAN, not a dNSName one.
    CHECK_EQ(sanText(leaf.cert), std::string("IP:192.0.2.7"));
    CHECK_EQ(X509_check_ip_asc(leaf.cert, "192.0.2.7", 0), 1);
}

TEST(ca_leaf_without_ensure_fails) {
    adb::CertAuthority ca;
    adb::CertAuthority::Leaf leaf = ca.leafFor("example.com");
    CHECK(leaf.cert == nullptr);
    CHECK(leaf.key == nullptr);
}

TEST(ca_tls_contexts) {
    TempDir tmp("ctx");
    adb::CertAuthority ca;
    CHECK(ca.ensure(tmp.path));

    SSL_CTX *server = adb::makeServerCtx(ca);
    CHECK(server != nullptr);
    if (server) {
        CHECK(SSL_CTX_get_app_data(server) == static_cast<void *>(&ca));
        CHECK_EQ((long)SSL_CTX_get_min_proto_version(server), (long)TLS1_2_VERSION);
        SSL_CTX_free(server);
    }

    SSL_CTX *client = adb::makeClientCtx();
    CHECK(client != nullptr);
    if (client) {
        CHECK_EQ((long)SSL_CTX_get_min_proto_version(client), (long)TLS1_2_VERSION);
        CHECK_EQ(SSL_CTX_get_verify_mode(client), SSL_VERIFY_PEER);
        SSL_CTX_free(client);
    }
}
