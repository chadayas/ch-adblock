#include "adb/parser.hpp"
#include "harness.hpp"

using namespace adb;

namespace {
Rule parse(std::string_view s) {
    auto r = parseNetworkRule(s);
    if (!r) {
        ::t::fail(__FILE__, __LINE__, std::string("parseNetworkRule rejected: ") + std::string(s));
        return Rule{};
    }
    return std::move(*r);
}
} // namespace

// ---------------------------------------------------------------------------
// classify
// ---------------------------------------------------------------------------

TEST(classify_empty_and_comments) {
    CHECK(classify("") == LineKind::Empty);
    CHECK(classify("   \t ") == LineKind::Empty);
    CHECK(classify("! a comment") == LineKind::Empty);
    CHECK(classify("[Adblock Plus 2.0]") == LineKind::Empty);
    CHECK(classify("#") == LineKind::Empty);
    CHECK(classify("# a hash comment") == LineKind::Empty);
}

TEST(classify_cosmetic) {
    CHECK(classify("##.ad") == LineKind::Cosmetic);
    CHECK(classify("example.com##.ad") == LineKind::Cosmetic);
    CHECK(classify("example.com#@#.ad") == LineKind::Cosmetic);
    CHECK(classify("example.com#?#div:has(a)") == LineKind::Cosmetic);
    CHECK(classify("example.com#$#body { x: y }") == LineKind::Cosmetic);
    CHECK(classify("example.com#%#//scriptlet('a')") == LineKind::Cosmetic);
    CHECK(classify("example.com$$script[data-x]") == LineKind::Cosmetic);
    CHECK(classify("example.com$@$script") == LineKind::Cosmetic);
    CHECK(classify("~a.com,b.com##.ad") == LineKind::Cosmetic);
}

TEST(classify_network_not_cosmetic) {
    CHECK(classify("||ezojs.com^") == LineKind::Network);
    // A `##` living inside a URL path must NOT make the line cosmetic.
    CHECK(classify("||x.com/a##b") == LineKind::Network);
    CHECK(classify("||x.com^$domain=y.com") == LineKind::Network);
    CHECK(classify("/banner/*") == LineKind::Network);
}

// ---------------------------------------------------------------------------
// parseNetworkRule
// ---------------------------------------------------------------------------

TEST(parse_domain_anchor) {
    const Rule r = parse("||ezojs.com^");
    CHECK(r.domainAnchor);
    CHECK(!r.anchorStart);
    CHECK(!r.anchorEnd);
    CHECK(!r.isException);
    CHECK(!r.isRegex);
    CHECK_EQ(r.pattern, std::string("ezojs.com^"));
    CHECK_EQ(r.shortcut, std::string("ezojs"));
}

TEST(parse_exception_with_type) {
    const Rule r = parse("@@||a.com/x$script");
    CHECK(r.isException);
    CHECK(r.domainAnchor);
    CHECK_EQ((unsigned)r.typesAllow, (unsigned)CT_Script);
    CHECK_EQ((unsigned)r.typesDeny, 0u);
    CHECK_EQ(r.pattern, std::string("a.com/x"));
}

TEST(parse_regex) {
    const Rule r = parse("/banner\\d+/$image");
    CHECK(r.isRegex);
    CHECK(!r.domainAnchor);
    CHECK_EQ(r.pattern, std::string("banner\\d+"));
    CHECK_EQ((unsigned)r.typesAllow, (unsigned)CT_Image);
    CHECK(r.matchesPattern("http://x.com/banner12.png"));
    CHECK(!r.matchesPattern("http://x.com/banner.png"));
}

TEST(parse_unknown_modifier_rejected) {
    CHECK(!parseNetworkRule("||a.com^$replace=/a/b/").has_value());
    CHECK(!parseNetworkRule("||a.com^$csp=script-src none").has_value());
    CHECK(!parseNetworkRule("||a.com^$redirect=noopjs").has_value());
    CHECK(!parseNetworkRule("||a.com^$hls=/ad/").has_value());
    CHECK(!parseNetworkRule("||a.com^$cookie=x").has_value());
    CHECK(!parseNetworkRule("||a.com^$app=chrome.exe").has_value());
    CHECK(!parseNetworkRule("||a.com^$header=x:y").has_value());
    CHECK(!parseNetworkRule("||a.com^$stealth").has_value());
    CHECK(!parseNetworkRule("||a.com^$jsonprune=\\$..ads").has_value());
    CHECK(!parseNetworkRule("||a.com^$permissions=autoplay=()").has_value());
    CHECK(!parseNetworkRule("||a.com^$object").has_value());
}

TEST(parse_anchors) {
    const Rule s = parse("|http://a.com/x");
    CHECK(s.anchorStart);
    CHECK(!s.domainAnchor);
    CHECK_EQ(s.pattern, std::string("http://a.com/x"));

    const Rule e = parse("/ads.gif|");
    CHECK(e.anchorEnd);
    CHECK_EQ(e.pattern, std::string("/ads.gif"));

    const Rule b = parse("|http://a.com/x|");
    CHECK(b.anchorStart);
    CHECK(b.anchorEnd);
}

TEST(parse_third_party) {
    CHECK(parse("||a.com^$third-party").thirdParty == ThirdParty::Only);
    CHECK(parse("||a.com^$3p").thirdParty == ThirdParty::Only);
    CHECK(parse("||a.com^$~third-party").thirdParty == ThirdParty::NotOnly);
    CHECK(parse("||a.com^").thirdParty == ThirdParty::Any);
}

TEST(parse_domain_lists) {
    const Rule r = parse("||a.com^$domain=Foo.com|~bar.foo.com|baz.org");
    CHECK_EQ(r.includeDomains.size(), (size_t)2);
    CHECK_EQ(r.includeDomains[0], std::string("foo.com"));
    CHECK_EQ(r.includeDomains[1], std::string("baz.org"));
    CHECK_EQ(r.excludeDomains.size(), (size_t)1);
    CHECK_EQ(r.excludeDomains[0], std::string("bar.foo.com"));

    const Rule f = parse("||a.com^$from=x.com");
    CHECK_EQ(f.includeDomains.size(), (size_t)1);
    CHECK_EQ(f.includeDomains[0], std::string("x.com"));
}

TEST(parse_denyallow_and_method) {
    const Rule d = parse("*$denyallow=good.com|ok.org,domain=site.com");
    CHECK_EQ(d.denyAllow.size(), (size_t)2);
    CHECK_EQ(d.denyAllow[1], std::string("ok.org"));

    const Rule m = parse("||a.com^$method=get|head");
    CHECK_EQ((unsigned)m.methods, (unsigned)(M_GET | M_HEAD));
    CHECK_EQ((unsigned)m.methodsDeny, 0u);

    const Rule n = parse("||a.com^$method=~post");
    CHECK_EQ((unsigned)n.methods, 0u);
    CHECK_EQ((unsigned)n.methodsDeny, (unsigned)M_POST);

    CHECK(!parseNetworkRule("||a.com^$method=frobnicate").has_value());
}

TEST(parse_flags_and_removeparam) {
    const Rule r = parse("||a.com^$important,match-case");
    CHECK(r.isImportant);
    CHECK(r.matchCase);

    const Rule bf = parse("||a.com^$badfilter");
    CHECK(bf.isBadfilter);

    const Rule bare = parse("||a.com^$removeparam");
    CHECK(bare.removeAllParams);
    CHECK(bare.removeParams.empty());

    const Rule rp = parse("||a.com^$removeparam=utm_source|gclid");
    CHECK(!rp.removeAllParams);
    CHECK_EQ(rp.removeParams.size(), (size_t)2);
    CHECK_EQ(rp.removeParams[0], std::string("utm_source"));

    // Regex / inverted removeparam forms are not implemented -> rejected.
    CHECK(!parseNetworkRule("||a.com^$removeparam=/^utm_/").has_value());
    CHECK(!parseNetworkRule("||a.com^$removeparam=~keep").has_value());
}

TEST(parse_negated_types_and_all) {
    const Rule r = parse("||a.com^$~script,~image");
    CHECK_EQ((unsigned)r.typesAllow, 0u);
    CHECK_EQ((unsigned)r.typesDeny, (unsigned)(CT_Script | CT_Image));

    const Rule a = parse("||a.com^$all");
    CHECK_EQ((unsigned)a.typesAllow, 0u);

    const Rule c = parse("||a.com^$css,xhr");
    CHECK_EQ((unsigned)c.typesAllow, (unsigned)(CT_Stylesheet | CT_XmlHttpRequest));
}

TEST(parse_case_folding) {
    CHECK_EQ(parse("||EXAMPLE.com/Ads").pattern, std::string("example.com/ads"));
    CHECK_EQ(parse("||EXAMPLE.com/Ads$match-case").pattern, std::string("EXAMPLE.com/Ads"));
}

TEST(parse_empty_pattern) {
    // Nothing to match on and no domain restriction -> reject.
    CHECK(!parseNetworkRule("$script").has_value());
    // A $domain restriction makes an empty pattern meaningful.
    CHECK(parseNetworkRule("$domain=a.com").has_value());
}

TEST(parse_dollar_in_regex_body_is_not_a_modifier_sep) {
    const Rule r = parse("/ads\\.js$/");
    CHECK(r.isRegex);
    CHECK_EQ(r.pattern, std::string("ads\\.js$"));
}

// ---------------------------------------------------------------------------
// extractShortcut
// ---------------------------------------------------------------------------

TEST(shortcut_basic) {
    // `/` is a perfectly good literal for a non-regex pattern.
    CHECK_EQ(extractShortcut("/ads/*.gif", false), std::string("/ads/"));
    CHECK_EQ(extractShortcut("ezojs.com^", false), std::string("ezojs"));
    CHECK_EQ(extractShortcut("example.com/ads.js", false), std::string("example"));
    CHECK_EQ(extractShortcut("doubleclick.net^", false), std::string("doubleclick"));
}

TEST(shortcut_too_short) {
    CHECK_EQ(extractShortcut("a.b.c", false), std::string(""));
    CHECK_EQ(extractShortcut("*", false), std::string(""));
    CHECK_EQ(extractShortcut("", false), std::string(""));
    CHECK_EQ(extractShortcut("abcd", false, 5), std::string(""));
    CHECK_EQ(extractShortcut("abcde", false, 5), std::string("abcde"));
}

TEST(shortcut_regex) {
    CHECK_EQ(extractShortcut("tracker\\d+\\.js", true), std::string("tracker"));
    CHECK_EQ(extractShortcut("banner\\d+", true), std::string("banner"));
    // Top-level alternation makes the pattern unindexable.
    CHECK_EQ(extractShortcut("advertising|marketing", true), std::string(""));
    // A group is conditional: never index inside it.
    CHECK_EQ(extractShortcut("(verylongoptional)?realpart", true), std::string("realpart"));
    // `?` makes the preceding char optional.
    CHECK_EQ(extractShortcut("adsx?", true), std::string("ads"));
    // `/` is a metachar inside a regex body.
    CHECK_EQ(extractShortcut("ads/banners", true), std::string("banners"));
}

// ---------------------------------------------------------------------------
// Rule::matchesPattern
// ---------------------------------------------------------------------------

TEST(match_domain_anchor) {
    const Rule r = parse("||example.com^");
    CHECK(r.matchesPattern("http://example.com/"));
    CHECK(r.matchesPattern("https://www.example.com/x"));
    CHECK(r.matchesPattern("https://a.b.example.com:8080/x"));
    CHECK(r.matchesPattern("https://example.com"));           // `^` == end-of-URL
    CHECK(!r.matchesPattern("https://notexample.com/"));
    CHECK(!r.matchesPattern("https://other.com/example.com/")); // path, not host
}

TEST(match_anchors) {
    const Rule s = parse("|https://a.com/");
    CHECK(s.matchesPattern("https://a.com/x"));
    CHECK(!s.matchesPattern("http://b.com/https://a.com/"));

    const Rule e = parse("/ads.gif|");
    CHECK(e.matchesPattern("http://x.com/ads.gif"));
    CHECK(!e.matchesPattern("http://x.com/ads.gif?q=1"));
}

TEST(match_wildcards) {
    const Rule r = parse("/ads/*.gif");
    CHECK(r.matchesPattern("http://x.com/ads/a/b/c.gif"));
    CHECK(r.matchesPattern("http://x.com/ads/.gif"));
    CHECK(!r.matchesPattern("http://x.com/ad/.gif"));
}

TEST(match_separator) {
    const Rule r = parse("||a.com^b");
    CHECK(r.matchesPattern("http://a.com/b"));
    CHECK(r.matchesPattern("http://a.com?b"));
    CHECK(!r.matchesPattern("http://a.comb"));
}

TEST(method_from_string) {
    CHECK(methodFromString("get") == M_GET);
    CHECK(methodFromString("POST") == M_POST);
    CHECK(methodFromString("OpTiOnS") == M_OPTIONS);
    CHECK(methodFromString("") == M_None);
    CHECK(methodFromString("nope") == M_None);
    CHECK(methodFromString("waytoolongmethod") == M_None);
}

TEST(request_make) {
    const Request r = Request::make("HTTPS://CDN.Example.COM/A.JS", "Example.com", CT_Script);
    CHECK_EQ(r.url, std::string("https://cdn.example.com/a.js"));
    CHECK_EQ(r.host, std::string("cdn.example.com"));
    CHECK_EQ(r.sourceHost, std::string("example.com"));
    CHECK(!r.thirdParty);

    const Request tp = Request::make("https://ads.doubleclick.net/x", "example.com", CT_Image);
    CHECK(tp.thirdParty);

    const Request top = Request::make("https://example.com/", "", CT_Document);
    CHECK(!top.thirdParty);
}
