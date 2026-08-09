#include "adb/cosmetic.hpp"
#include "harness.hpp"

using namespace adb;

namespace {
bool has(const std::string &css, std::string_view needle) {
    return css.find(needle) != std::string::npos;
}
} // namespace

TEST(cosmetic_generic_applies_everywhere) {
    CosmeticIndex c;
    CHECK(c.addRule("##.ad"));
    CHECK_EQ(c.genericCount(), (size_t)1);
    CHECK_EQ(c.specificCount(), (size_t)0);
    CHECK_EQ(c.cssFor("learncpp.com"), std::string(".ad{display:none!important}"));
    CHECK_EQ(c.cssFor("anything.example.org"), std::string(".ad{display:none!important}"));
}

TEST(cosmetic_specific_scoped_to_domain_and_subdomains) {
    CosmeticIndex c;
    CHECK(c.addRule("learncpp.com##span[id^=\"ezoic-pub-ad-placeholder-\"]"));
    CHECK_EQ(c.specificCount(), (size_t)1);
    CHECK_EQ(c.genericCount(), (size_t)0);

    const std::string want = "span[id^=\"ezoic-pub-ad-placeholder-\"]{display:none!important}";
    CHECK_EQ(c.cssFor("learncpp.com"), want);
    CHECK_EQ(c.cssFor("www.learncpp.com"), want);
    CHECK_EQ(c.cssFor("example.com"), std::string(""));
    CHECK_EQ(c.cssFor("notlearncpp.com"), std::string(""));
}

TEST(cosmetic_exception_is_host_scoped) {
    CosmeticIndex c;
    CHECK(c.addRule("##.ad"));
    CHECK(c.addRule("learncpp.com#@#.ad"));
    CHECK_EQ(c.cssFor("learncpp.com"), std::string(""));
    CHECK_EQ(c.cssFor("www.learncpp.com"), std::string(""));
    CHECK_EQ(c.cssFor("example.com"), std::string(".ad{display:none!important}"));
}

TEST(cosmetic_global_exception) {
    CosmeticIndex c;
    CHECK(c.addRule("##.ad"));
    CHECK(c.addRule("#@#.ad"));
    CHECK_EQ(c.cssFor("anywhere.com"), std::string(""));
}

TEST(cosmetic_multiple_domains_and_negation) {
    CosmeticIndex c;
    CHECK(c.addRule("a.com,b.com,~sub.a.com##.banner"));
    CHECK_EQ(c.specificCount(), (size_t)2);
    CHECK(has(c.cssFor("a.com"), ".banner"));
    CHECK(has(c.cssFor("www.a.com"), ".banner"));
    CHECK(has(c.cssFor("b.com"), ".banner"));
    CHECK_EQ(c.cssFor("sub.a.com"), std::string(""));
    CHECK_EQ(c.cssFor("deep.sub.a.com"), std::string(""));
    CHECK_EQ(c.cssFor("c.com"), std::string(""));
}

TEST(cosmetic_extended_selectors_are_skipped) {
    CosmeticIndex c;
    // Recognised (return true) but never stored -- we emit plain CSS only.
    CHECK(c.addRule("example.com##div:has(> .ad)"));
    CHECK(c.addRule("example.com##div:contains(Sponsored)"));
    CHECK(c.addRule("example.com##div:has-text(Ads)"));
    CHECK(c.addRule("example.com##div:matches-css(width: 300px)"));
    CHECK(c.addRule("example.com##div:style(display: none)"));
    CHECK(c.addRule("example.com##div:xpath(//x)"));
    CHECK(c.addRule("example.com##div:upward(2)"));
    CHECK(c.addRule("example.com##div:nth-ancestor(2)"));
    CHECK(c.addRule("example.com##+js(nowebrtc)"));
    CHECK(c.addRule("example.com##script:inject(x)"));
    CHECK(c.addRule("example.com##div { color: red }"));
    CHECK_EQ(c.specificCount(), (size_t)0);
    CHECK_EQ(c.genericCount(), (size_t)0);
    CHECK_EQ(c.cssFor("example.com"), std::string(""));
}

TEST(cosmetic_other_masks_recognised_but_skipped) {
    CosmeticIndex c;
    CHECK(c.addRule("example.com#?#div:has(a)"));
    CHECK(c.addRule("example.com#@?#div:has(a)"));
    CHECK(c.addRule("example.com#$#body { padding: 0 }"));
    CHECK(c.addRule("example.com#@$#body { padding: 0 }"));
    CHECK(c.addRule("example.com#%#//scriptlet('abort-on-property-read', 'x')"));
    CHECK(c.addRule("example.com#@%#//scriptlet('x')"));
    CHECK(c.addRule("example.com$$script[data-ad]"));
    CHECK(c.addRule("example.com$@$script[data-ad]"));
    CHECK_EQ(c.specificCount(), (size_t)0);
    CHECK_EQ(c.genericCount(), (size_t)0);
}

TEST(cosmetic_rejects_non_cosmetic_and_empty_selector) {
    CosmeticIndex c;
    CHECK(!c.addRule("||example.com^"));
    CHECK(!c.addRule("! comment"));
    CHECK(!c.addRule("example.com##"));
    CHECK(!c.addRule("##"));
    CHECK_EQ(c.specificCount(), (size_t)0);
    CHECK_EQ(c.genericCount(), (size_t)0);
}

TEST(cosmetic_dedup_and_join) {
    CosmeticIndex c;
    CHECK(c.addRule("##.ad"));
    CHECK(c.addRule("example.com##.ad")); // same selector, must appear once
    CHECK(c.addRule("example.com##.promo"));
    const std::string css = c.cssFor("example.com");
    CHECK_EQ(css, std::string(".ad,.promo{display:none!important}"));
}

TEST(cosmetic_case_insensitive_domains) {
    CosmeticIndex c;
    CHECK(c.addRule("LearnCPP.com##.ad"));
    CHECK(has(c.cssFor("WWW.LEARNCPP.COM"), ".ad"));
}

TEST(cosmetic_exclusion_only_rule_is_not_stored) {
    // `~a.com##.x` has no include key and generic_ carries no exclusions, so
    // storing it would hide the element on exactly the host it exempts.
    CosmeticIndex c;
    CHECK(c.addRule("~a.com##.x"));
    CHECK_EQ(c.genericCount(), (size_t)0);
    CHECK_EQ(c.specificCount(), (size_t)0);
    CHECK_EQ(c.cssFor("b.com"), std::string(""));
}
