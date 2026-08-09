#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace adb::url {

// A non-owning split of an absolute URL. All views alias the input buffer,
// so the caller MUST keep it alive.
struct Parts {
    std::string_view scheme; // "http" / "https", lowercase only if input was
    std::string_view host;   // no port, no userinfo
    std::string_view path;   // begins with '/', or empty
    std::string_view query;  // without '?'
    uint16_t port = 0;       // 0 => scheme default
    bool valid = false;
};

// Parses absolute-form URLs ("https://host:port/path?query"). Returns
// valid=false on anything it cannot make sense of. Does not decode escapes.
Parts split(std::string_view url);

// Lowercases ASCII in place-ish (returns a new string). Hosts only.
std::string lower(std::string_view s);

// True if `host` is `domain` or a subdomain of it.
//   isSubdomainOf("a.b.example.com", "example.com") == true
//   isSubdomainOf("notexample.com",  "example.com") == false
// Both arguments are expected lowercase.
bool isSubdomainOf(std::string_view host, std::string_view domain);

// Registrable domain ("example.co.uk" from "www.example.co.uk"), using a
// compact built-in list of multi-label public suffixes. Not a full PSL --
// good enough for third-party determination. Returns `host` unchanged when
// it has fewer labels than the suffix requires.
std::string_view registrableDomain(std::string_view host);

// Third-party == registrable domains differ. Empty `sourceHost` => false
// (a top-level document navigation is never third-party).
bool isThirdParty(std::string_view host, std::string_view sourceHost);

// Adblock `^` separator: any char that is not a letter, digit, or one of
// `_ - . %`. End-of-string also counts as a separator (handled by matcher).
bool isSeparator(char c);

} // namespace adb::url
