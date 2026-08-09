#include "adb/cosmetic.hpp"
#include "adb/log.hpp"
#include "harness.hpp"

using namespace adb;

namespace {
bool has(const std::string &css, std::string_view needle) {
    return css.find(needle) != std::string::npos;
}

// Wraps a body in enough markup that the attribute scanner sees real tags.
std::string page(std::string_view body) {
    return "<!doctype html><html><body>" + std::string(body) + "</body></html>";
}

// Silences the one-shot "called before finalize()" warning during tests.
struct QuietLog {
    LogLevel saved = g_log_level;
    QuietLog() { g_log_level = LogLevel::Error; }
    ~QuietLog() { g_log_level = saved; }
};
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

// --- token reduction -------------------------------------------------------

TEST(cosmetic_token_is_the_longest_name) {
    // `div.a.advertisement-box` must key on `advertisement-box`, not `a`.
    CosmeticIndex c;
    CHECK(c.addRule("##div.a.advertisement-box"));
    c.finalize();
    CHECK_EQ(c.genericAlwaysCount(), (size_t)0); // reducible, so not unconditional

    const std::string hit = c.cssFor("x.com", page("<div class=\"advertisement-box\"></div>"));
    CHECK(has(hit, "div.a.advertisement-box"));
    // A page carrying only the short name must not pull the rule in.
    CHECK_EQ(c.cssFor("x.com", page("<div class=\"a\"></div>")), std::string(""));
    CHECK_EQ(c.cssFor("x.com", page("<div class=\"nothing\"></div>")), std::string(""));
}

TEST(cosmetic_prefix_attribute_is_always_emitted) {
    CosmeticIndex c;
    CHECK(c.addRule("##[id^=\"ezoic-pub-ad-placeholder-\"]"));
    c.finalize();
    CHECK_EQ(c.genericAlwaysCount(), (size_t)1);
    // The prefix is not a token, so it must survive a page that never mentions it.
    const std::string css = c.cssFor("x.com", page("<div class=\"unrelated\"></div>"));
    CHECK_EQ(css, std::string("[id^=\"ezoic-pub-ad-placeholder-\"]{display:none!important}"));
}

TEST(cosmetic_substring_and_suffix_attributes_are_always_emitted) {
    CosmeticIndex c;
    CHECK(c.addRule("##iframe[src*=\"doubleclick.net\"]"));
    CHECK(c.addRule("##a[href$=\"/promo\"]"));
    CHECK(c.addRule("##div[class~=\"sponsored\"]"));
    CHECK(c.addRule("##div[data-ad]"));
    CHECK(c.addRule("##ins"));
    c.finalize();
    CHECK_EQ(c.genericAlwaysCount(), (size_t)5);
    const std::string css = c.cssFor("x.com", page("<p>nothing here</p>"));
    CHECK(has(css, "iframe[src*=\"doubleclick.net\"]"));
    CHECK(has(css, "a[href$=\"/promo\"]"));
    CHECK(has(css, "div[class~=\"sponsored\"]"));
    CHECK(has(css, "div[data-ad]"));
    CHECK(has(css, "ins"));
}

TEST(cosmetic_class_token_gates_emission) {
    CosmeticIndex c;
    CHECK(c.addRule("##.ad-banner"));
    c.finalize();
    CHECK_EQ(c.genericAlwaysCount(), (size_t)0);
    CHECK_EQ(c.cssFor("x.com", page("<div class=\"x ad-banner y\">hi</div>")),
             std::string(".ad-banner{display:none!important}"));
    CHECK_EQ(c.cssFor("x.com", page("<div class=\"x y\">hi</div>")), std::string(""));
    CHECK_EQ(c.cssFor("x.com", page("<div>hi</div>")), std::string(""));
}

TEST(cosmetic_exact_attribute_match_on_class_or_id_is_a_token) {
    CosmeticIndex c;
    CHECK(c.addRule("##div[id=\"promo-slot\"]"));
    CHECK(c.addRule("##span[class='promo-word']"));
    CHECK(c.addRule("##b[id=promo-bare]"));
    c.finalize();
    CHECK_EQ(c.genericAlwaysCount(), (size_t)0);
    CHECK(has(c.cssFor("x.com", page("<div id=\"promo-slot\"></div>")), "div[id=\"promo-slot\"]"));
    CHECK(has(c.cssFor("x.com", page("<span class=\"promo-word\"></span>")), "span[class='promo-word']"));
    CHECK(has(c.cssFor("x.com", page("<b id=\"promo-bare\"></b>")), "b[id=promo-bare]"));
    CHECK_EQ(c.cssFor("x.com", page("<div id=\"other\"></div>")), std::string(""));
}

TEST(cosmetic_unquoted_html_attributes_are_scanned) {
    // learncpp.com serves `<div class=cf_monitor>` and unquoted ids.
    CosmeticIndex c;
    CHECK(c.addRule("##.cf_monitor"));
    CHECK(c.addRule("###ezoic-pub-ad-placeholder-101"));
    c.finalize();
    CHECK_EQ(c.genericAlwaysCount(), (size_t)0);

    const std::string css =
        c.cssFor("x.com", page("<span id=ezoic-pub-ad-placeholder-101></span>"
                               "<div class=cf_monitor>x</div>"));
    CHECK(has(css, ".cf_monitor"));
    CHECK(has(css, "#ezoic-pub-ad-placeholder-101"));
    // And the same names spelled with whitespace around '='.
    CHECK(has(c.cssFor("x.com", page("<div class = cf_monitor>x</div>")), ".cf_monitor"));
}

TEST(cosmetic_longer_attribute_names_contribute_no_tokens) {
    CosmeticIndex c;
    CHECK(c.addRule("##.ad-banner"));
    CHECK(c.addRule("###foo"));
    c.finalize();
    // `data-class` is not `class`; `itemid` is not `id`.
    CHECK_EQ(c.cssFor("x.com", page("<div data-class=\"ad-banner\" itemid=\"foo\"></div>")),
             std::string(""));
    // Sanity: the real attribute names do pull them in.
    const std::string css = c.cssFor("x.com", page("<div class=\"ad-banner\" id=\"foo\"></div>"));
    CHECK(has(css, ".ad-banner"));
    CHECK(has(css, "#foo"));
}

TEST(cosmetic_selector_lists_and_negations_are_always_emitted) {
    // Neither alternative of a list is required, and a name inside :not() is
    // required to be *absent* -- reducing either way would stop hiding ads.
    CosmeticIndex c;
    CHECK(c.addRule("##.alpha-one, .beta-two"));
    CHECK(c.addRule("##div:not(.gamma-three)"));
    c.finalize();
    CHECK_EQ(c.genericAlwaysCount(), (size_t)2);
    const std::string css = c.cssFor("x.com", page("<p>nothing</p>"));
    CHECK(has(css, ".alpha-one, .beta-two"));
    CHECK(has(css, "div:not(.gamma-three)"));
}

TEST(cosmetic_qualified_selector_keeps_its_class_token) {
    // A prefix operator elsewhere does not stop `.ad-slot` being required.
    CosmeticIndex c;
    CHECK(c.addRule("##div.ad-slot[data-x^=\"y\"]"));
    c.finalize();
    CHECK_EQ(c.genericAlwaysCount(), (size_t)0);
    CHECK(has(c.cssFor("x.com", page("<div class=\"ad-slot\"></div>")), "div.ad-slot"));
    CHECK_EQ(c.cssFor("x.com", page("<div class=\"other\"></div>")), std::string(""));
}

TEST(cosmetic_specific_rules_ignore_the_document) {
    CosmeticIndex c;
    CHECK(c.addRule("learncpp.com##.site-promo"));
    CHECK(c.addRule("learncpp.com##span[id^=\"ezoic-pub-ad-placeholder-\"]"));
    c.finalize();
    const std::string empty = c.cssFor("www.learncpp.com", page("<p>nothing at all</p>"));
    CHECK(has(empty, ".site-promo"));
    CHECK(has(empty, "span[id^=\"ezoic-pub-ad-placeholder-\"]"));
    CHECK_EQ(c.cssFor("example.com", page("<div class=\"site-promo\"></div>")), std::string(""));
}

TEST(cosmetic_exceptions_subtract_in_both_forms) {
    CosmeticIndex c;
    CHECK(c.addRule("##.ad-banner"));
    CHECK(c.addRule("##[id^=\"ezoic-pub-ad-\"]"));
    CHECK(c.addRule("learncpp.com#@#.ad-banner"));
    CHECK(c.addRule("#@#[id^=\"ezoic-pub-ad-\"]"));
    c.finalize();

    const std::string html = page("<div class=\"ad-banner\"></div>");
    CHECK_EQ(c.cssFor("learncpp.com"), std::string(""));
    CHECK_EQ(c.cssFor("www.learncpp.com", html), std::string(""));
    // Host-scoped exception does not apply elsewhere; the global one still does.
    CHECK_EQ(c.cssFor("example.com"), std::string(".ad-banner{display:none!important}"));
    CHECK_EQ(c.cssFor("example.com", html), std::string(".ad-banner{display:none!important}"));
    CHECK_EQ(c.cssFor("example.com", page("<p>x</p>")), std::string(""));
}

TEST(cosmetic_two_arg_before_finalize_is_a_superset) {
    QuietLog quiet;
    CosmeticIndex c;
    CHECK(c.addRule("##.ad-banner"));
    CHECK(c.addRule("##.never-on-this-page"));
    CHECK(c.addRule("##[id^=\"ezoic-pub-ad-\"]"));
    // No finalize(): must fall back to the full generic list rather than hide less.
    const std::string css = c.cssFor("x.com", page("<p>nothing</p>"));
    CHECK_EQ(css, c.cssFor("x.com"));
    CHECK(has(css, ".ad-banner"));
    CHECK(has(css, ".never-on-this-page"));
}

TEST(cosmetic_finalize_is_idempotent_and_rebuilds_after_new_rules) {
    QuietLog quiet;
    CosmeticIndex c;
    CHECK(c.addRule("##.first-class"));
    c.finalize();
    c.finalize(); // must not double-index
    CHECK_EQ(c.cssFor("x.com", page("<div class=\"first-class\"></div>")),
             std::string(".first-class{display:none!important}"));

    CHECK(c.addRule("##[data-late]"));
    CHECK(c.addRule("##.second-class"));
    c.finalize();
    CHECK_EQ(c.genericAlwaysCount(), (size_t)1);
    const std::string css = c.cssFor("x.com", page("<div class=\"second-class\"></div>"));
    CHECK(has(css, ".second-class"));
    CHECK(has(css, "[data-late]"));
    CHECK(!has(css, ".first-class"));
}

TEST(cosmetic_reduction_never_drops_what_the_full_list_keeps) {
    CosmeticIndex c;
    CHECK(c.addRule("##.present-class"));
    CHECK(c.addRule("##.absent-class"));
    CHECK(c.addRule("###present-id"));
    CHECK(c.addRule("##ins[data-ad]"));
    CHECK(c.addRule("example.com##.host-rule"));
    c.finalize();

    const std::string html =
        page("<div class=\"present-class\"><span id=present-id></span></div>");
    const std::string full    = c.cssFor("example.com");
    const std::string reduced = c.cssFor("example.com", html);
    CHECK(reduced.size() < full.size());
    for (std::string_view s : {".present-class", "#present-id", "ins[data-ad]", ".host-rule"}) {
        CHECK(has(reduced, s));
        CHECK(has(full, s));
    }
    CHECK(!has(reduced, ".absent-class"));
    CHECK(has(full, ".absent-class"));
}
