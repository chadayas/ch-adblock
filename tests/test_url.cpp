#include "adb/url.hpp"
#include "harness.hpp"

using namespace adb;

TEST(url_split_full) {
    const std::string u = "https://u:p@a.b.co.uk:8443/x/y?z=1#f";
    const url::Parts p  = url::split(u);
    CHECK(p.valid);
    CHECK_EQ(p.scheme, std::string_view("https"));
    CHECK_EQ(p.host, std::string_view("a.b.co.uk"));
    CHECK_EQ(p.port, (uint16_t)8443);
    CHECK_EQ(p.path, std::string_view("/x/y"));
    CHECK_EQ(p.query, std::string_view("z=1"));
}

TEST(url_split_minimal) {
    const url::Parts p = url::split("http://example.com");
    CHECK(p.valid);
    CHECK_EQ(p.host, std::string_view("example.com"));
    CHECK_EQ(p.port, (uint16_t)0);
    CHECK(p.path.empty());
    CHECK(p.query.empty());
}

TEST(url_split_root_and_empty_query) {
    const url::Parts p = url::split("http://example.com/?");
    CHECK(p.valid);
    CHECK_EQ(p.path, std::string_view("/"));
    CHECK(p.query.empty());
}

TEST(url_split_fragment_only) {
    const url::Parts p = url::split("https://example.com/a#frag?notquery");
    CHECK(p.valid);
    CHECK_EQ(p.path, std::string_view("/a"));
    CHECK(p.query.empty());
}

TEST(url_split_ipv6) {
    const url::Parts p = url::split("http://[::1]:8080/x");
    CHECK(p.valid);
    CHECK_EQ(p.host, std::string_view("::1"));
    CHECK_EQ(p.port, (uint16_t)8080);
    CHECK_EQ(p.path, std::string_view("/x"));
}

TEST(url_split_userinfo_with_at_in_path) {
    const url::Parts p = url::split("https://example.com/@user/feed");
    CHECK(p.valid);
    CHECK_EQ(p.host, std::string_view("example.com"));
    CHECK_EQ(p.path, std::string_view("/@user/feed"));
}

TEST(url_split_garbage) {
    CHECK(!url::split("").valid);
    CHECK(!url::split("not a url").valid);
    CHECK(!url::split("://example.com").valid);
    CHECK(!url::split("http://").valid);
    CHECK(!url::split("1http://example.com").valid);
    CHECK(!url::split("http://example.com:notaport/").valid);
    CHECK(!url::split("http://ex ample.com/").valid);
    CHECK(!url::split("http://example.com:99999/").valid);
}

TEST(url_lower) {
    CHECK_EQ(url::lower("HTTPS://EXAMPLE.CoM/A"), std::string("https://example.com/a"));
}

TEST(url_is_subdomain_of) {
    CHECK(url::isSubdomainOf("a.b.example.com", "example.com"));
    CHECK(url::isSubdomainOf("example.com", "example.com"));
    CHECK(!url::isSubdomainOf("notexample.com", "example.com"));
    CHECK(!url::isSubdomainOf("example.com", "a.example.com"));
    CHECK(!url::isSubdomainOf("example.com", ""));
    CHECK(!url::isSubdomainOf("", "example.com"));
}

TEST(url_registrable_domain) {
    CHECK_EQ(url::registrableDomain("a.b.co.uk"), std::string_view("b.co.uk"));
    CHECK_EQ(url::registrableDomain("b.co.uk"), std::string_view("b.co.uk"));
    CHECK_EQ(url::registrableDomain("co.uk"), std::string_view("co.uk"));
    CHECK_EQ(url::registrableDomain("www.example.com"), std::string_view("example.com"));
    CHECK_EQ(url::registrableDomain("example.com"), std::string_view("example.com"));
    CHECK_EQ(url::registrableDomain("localhost"), std::string_view("localhost"));
    CHECK_EQ(url::registrableDomain("deep.a.b.co.uk"), std::string_view("b.co.uk"));
    // github.io is a multi-label suffix, so the user label is registrable.
    CHECK_EQ(url::registrableDomain("user.github.io"), std::string_view("user.github.io"));
    CHECK_EQ(url::registrableDomain("x.user.github.io"), std::string_view("user.github.io"));
    // Not in the table -> plain last-two.
    CHECK_EQ(url::registrableDomain("a.b.co.zz"), std::string_view("co.zz"));
}

TEST(url_third_party) {
    CHECK(!url::isThirdParty("cdn.example.com", "example.com"));
    CHECK(url::isThirdParty("ads.doubleclick.net", "example.com"));
    // Empty source == top-level navigation, never third-party.
    CHECK(!url::isThirdParty("ads.doubleclick.net", ""));
    CHECK(!url::isThirdParty("a.b.co.uk", "c.b.co.uk"));
    CHECK(url::isThirdParty("a.b.co.uk", "c.d.co.uk"));
}

TEST(url_is_separator) {
    for (char c : std::string_view("abzABZ019_-.%")) CHECK(!url::isSeparator(c));
    for (char c : std::string_view("/?&=:;,#^ +*|")) CHECK(url::isSeparator(c));
}
