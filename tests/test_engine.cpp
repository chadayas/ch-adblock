#include "adb/engine.hpp"
#include "harness.hpp"

#include <initializer_list>

using namespace adb;

namespace {

Engine build(std::initializer_list<const char *> lines) {
    Engine e;
    for (const char *l : lines) e.addLine(l);
    e.finalize();
    return e;
}

const char *kBase[] = {
    "||ezojs.com^",
    "||doubleclick.net^$third-party",
    "@@||learncpp.com^",
    "||example.com/ads.js",
    "/tracker\\d+\\.js/",
};

Engine baseEngine() {
    Engine e;
    for (const char *l : kBase) e.addLine(l);
    e.finalize();
    return e;
}

} // namespace

TEST(engine_stats_after_load) {
    const Engine e = baseEngine();
    CHECK_EQ(e.stats().rulesTotal, (size_t)5);
    CHECK_EQ(e.stats().byShortcut, (size_t)5);
    CHECK_EQ(e.stats().byDomain, (size_t)0);
    CHECK_EQ(e.stats().leftovers, (size_t)0);
    CHECK_EQ(e.stats().badfilters, (size_t)0);
}

TEST(engine_blocks_and_allows) {
    const Engine e = baseEngine();

    // The motivating case from notes/02 section 8.
    const auto ezo =
        e.match(Request::make("https://www.ezojs.com/ezoic/sa.min.js", "learncpp.com", CT_Script));
    CHECK(ezo);
    CHECK(ezo.blocked);
    CHECK_EQ(ezo.rule->text, std::string("||ezojs.com^"));

    // $third-party honoured both ways.
    CHECK(e.match(Request::make("https://ad.doubleclick.net/x", "learncpp.com", CT_Image)).blocked);
    CHECK(
        !e.match(Request::make("https://ad.doubleclick.net/x", "doubleclick.net", CT_Image)).rule);

    // Plain path rule.
    CHECK(e.match(Request::make("https://example.com/ads.js", "learncpp.com", CT_Script)).blocked);
    CHECK(!e.match(Request::make("https://example.com/app.js", "learncpp.com", CT_Script)).rule);

    // Regex rule, reached through its "tracker" shortcut.
    CHECK(e.match(Request::make("https://cdn.foo.com/tracker42.js", "learncpp.com", CT_Script))
              .blocked);
    CHECK(!e.match(Request::make("https://cdn.foo.com/track.js", "learncpp.com", CT_Script)).rule);

    // The document itself is allowlisted.
    const auto doc = e.match(Request::make("https://www.learncpp.com/", "", CT_Document));
    CHECK(doc);
    CHECK(!doc.blocked);
    CHECK(doc.rule->isException);
}

TEST(engine_badfilter_removes_rule) {
    Engine before = build({"||ezojs.com^"});
    CHECK(before.match(Request::make("https://www.ezojs.com/x.js", "learncpp.com", CT_Script))
              .blocked);

    Engine after = build({"||ezojs.com^", "||ezojs.com^$badfilter"});
    CHECK_EQ(after.stats().rulesTotal, (size_t)0);
    CHECK_EQ(after.stats().badfilters, (size_t)1);
    CHECK(!after.match(Request::make("https://www.ezojs.com/x.js", "learncpp.com", CT_Script))
               .rule);
}

TEST(engine_badfilter_keeps_modifier_mismatch) {
    // $badfilter only disables the rule with the identical remaining modifiers.
    Engine e = build({"||ezojs.com^$script", "||ezojs.com^$image,badfilter"});
    CHECK_EQ(e.stats().rulesTotal, (size_t)1);
    CHECK(e.match(Request::make("https://www.ezojs.com/x.js", "learncpp.com", CT_Script)).blocked);

    Engine m = build({"||ezojs.com^$script", "||ezojs.com^$script,badfilter"});
    CHECK_EQ(m.stats().rulesTotal, (size_t)0);
}

TEST(engine_exception_beats_blocking) {
    Engine e   = build({"||ads.com^", "@@||ads.com^"});
    const auto r = e.match(Request::make("https://ads.com/x.js", "site.com", CT_Script));
    CHECK(r);
    CHECK(!r.blocked);
    CHECK(r.rule->isException);

    // Rule order must not matter.
    Engine rev   = build({"@@||ads.com^", "||ads.com^"});
    CHECK(!rev.match(Request::make("https://ads.com/x.js", "site.com", CT_Script)).blocked);
}

TEST(engine_important_beats_exception) {
    Engine e   = build({"||imp.com^$important", "@@||imp.com^"});
    const auto r = e.match(Request::make("https://imp.com/x.js", "site.com", CT_Script));
    CHECK(r);
    CHECK(r.blocked);
    CHECK(r.rule->isImportant);

    // ...and an $important exception beats an $important blocking rule.
    Engine both = build({"||imp.com^$important", "@@||imp.com^$important"});
    const auto b = both.match(Request::make("https://imp.com/x.js", "site.com", CT_Script));
    CHECK(b);
    CHECK(!b.blocked);
}

TEST(engine_content_type_filter) {
    Engine e = build({"||cdn.com/x$script"});
    CHECK(e.match(Request::make("https://cdn.com/x", "site.com", CT_Script)).blocked);
    CHECK(!e.match(Request::make("https://cdn.com/x", "site.com", CT_Image)).rule);

    Engine n = build({"||cdn.com/x$~script"});
    CHECK(!n.match(Request::make("https://cdn.com/x", "site.com", CT_Script)).rule);
    CHECK(n.match(Request::make("https://cdn.com/x", "site.com", CT_Image)).blocked);
}

TEST(engine_method_filter) {
    Engine e = build({"||cdn.com/x$method=post"});
    CHECK(e.match(Request::make("https://cdn.com/x", "site.com", CT_Other, M_POST)).blocked);
    CHECK(!e.match(Request::make("https://cdn.com/x", "site.com", CT_Other, M_GET)).rule);
}

TEST(engine_domain_table) {
    // No usable shortcut -> the rule must land in rules_by_domain.
    Engine e = build({"$domain=site.com,script"});
    CHECK_EQ(e.stats().byDomain, (size_t)1);
    CHECK_EQ(e.stats().byShortcut, (size_t)0);
    CHECK_EQ(e.stats().leftovers, (size_t)0);
    CHECK(e.match(Request::make("https://any.cdn/x.js", "www.site.com", CT_Script)).blocked);
    CHECK(!e.match(Request::make("https://any.cdn/x.js", "other.com", CT_Script)).rule);
}

TEST(engine_domain_exclusion) {
    Engine e = build({"||cdn.com/x$domain=~safe.com"});
    CHECK(e.match(Request::make("https://cdn.com/x", "site.com", CT_Script)).blocked);
    CHECK(!e.match(Request::make("https://cdn.com/x", "www.safe.com", CT_Script)).rule);
}

TEST(engine_denyallow) {
    Engine e = build({"*/ads$denyallow=good.com,domain=site.com"});
    CHECK(e.match(Request::make("https://bad.com/ads", "site.com", CT_Other)).blocked);
    CHECK(!e.match(Request::make("https://cdn.good.com/ads", "site.com", CT_Other)).rule);
}

TEST(engine_leftovers) {
    // Alternation regex is unindexable -> leftovers, still matched linearly.
    Engine e = build({"/adserver|adhost/"});
    CHECK_EQ(e.stats().leftovers, (size_t)1);
    CHECK(e.match(Request::make("https://x.com/adhost/a", "site.com", CT_Other)).blocked);
    CHECK(!e.match(Request::make("https://x.com/nothing", "site.com", CT_Other)).rule);
}

TEST(engine_short_shortcut_is_still_indexed) {
    // "abc" is shorter than the 4-byte gram, so it takes the linear side list.
    Engine e = build({"||abc.io^"});
    CHECK_EQ(e.stats().byShortcut, (size_t)1);
    CHECK_EQ(e.stats().leftovers, (size_t)0);
    CHECK(e.match(Request::make("https://abc.io/x", "site.com", CT_Other)).blocked);
    CHECK(!e.match(Request::make("https://abd.io/x", "site.com", CT_Other)).rule);
}

TEST(engine_skips_unsupported_lines) {
    Engine e;
    CHECK(!e.addLine("! comment"));
    CHECK(!e.addLine(""));
    CHECK(!e.addLine("||a.com^$replace=/x/y/"));
    CHECK(e.addLine("||a.com^"));
    CHECK(e.addLine("example.com##.ad"));
    e.finalize();
    CHECK_EQ(e.stats().linesSkipped, (size_t)1);
    CHECK_EQ(e.stats().cosmetic, (size_t)1);
    CHECK_EQ(e.stats().rulesTotal, (size_t)1);
}

TEST(engine_cosmetic_css) {
    Engine e = build({"##.ad", "learncpp.com##span[id^=\"ezoic-pub-ad-placeholder-\"]"});
    const std::string css = e.cosmeticCss("www.learncpp.com");
    CHECK(css.find(".ad") != std::string::npos);
    CHECK(css.find("ezoic-pub-ad-placeholder-") != std::string::npos);
    CHECK(css.find("{display:none!important}") != std::string::npos);
}

TEST(engine_finalize_is_idempotent) {
    Engine e = baseEngine();
    const size_t total = e.stats().rulesTotal;
    e.finalize();
    e.finalize();
    CHECK_EQ(e.stats().rulesTotal, total);
    CHECK(e.match(Request::make("https://www.ezojs.com/x.js", "learncpp.com", CT_Script)).blocked);
}

// ---------------------------------------------------------------------------
// guessContentType
// ---------------------------------------------------------------------------

TEST(guess_from_sec_fetch_dest) {
    CHECK(guessContentType("document", "", "") == CT_Document);
    CHECK(guessContentType("iframe", "", "") == CT_Subdocument);
    CHECK(guessContentType("frame", "", "") == CT_Subdocument);
    CHECK(guessContentType("script", "", "") == CT_Script);
    CHECK(guessContentType("style", "", "") == CT_Stylesheet);
    CHECK(guessContentType("image", "", "") == CT_Image);
    CHECK(guessContentType("font", "", "") == CT_Font);
    CHECK(guessContentType("video", "", "") == CT_Media);
    CHECK(guessContentType("audio", "", "") == CT_Media);
    CHECK(guessContentType("track", "", "") == CT_Media);
    CHECK(guessContentType("empty", "", "") == CT_XmlHttpRequest);
    CHECK(guessContentType("websocket", "", "") == CT_WebSocket);
    // Sec-Fetch-Dest wins over everything else.
    CHECK(guessContentType("image", "text/html", "/a.js") == CT_Image);
}

TEST(guess_from_accept) {
    CHECK(guessContentType("", "text/html,application/xhtml+xml", "/x") == CT_Document);
    CHECK(guessContentType("", "text/css,*/*;q=0.1", "/x") == CT_Stylesheet);
    CHECK(guessContentType("", "image/avif,image/webp,*/*", "/x") == CT_Image);
    CHECK(guessContentType("", "application/javascript", "/x") == CT_Script);
    CHECK(guessContentType("", "text/javascript", "/x") == CT_Script);
}

TEST(guess_from_extension) {
    CHECK(guessContentType("", "", "/a/b.js") == CT_Script);
    CHECK(guessContentType("", "", "/a/b.mjs") == CT_Script);
    CHECK(guessContentType("", "", "/a/b.css") == CT_Stylesheet);
    CHECK(guessContentType("", "", "/a/b.PNG") == CT_Image);
    CHECK(guessContentType("", "", "/a/b.svg?v=2") == CT_Image);
    CHECK(guessContentType("", "", "/a/b.woff2") == CT_Font);
    CHECK(guessContentType("", "", "/a/b.m3u8") == CT_Media);
    CHECK(guessContentType("", "", "/a/b.html") == CT_Document);
    CHECK(guessContentType("", "", "/a/b.unknown") == CT_Other);
    CHECK(guessContentType("", "", "/a/b") == CT_Other);
    CHECK(guessContentType("", "", "") == CT_Other);
    // A dot in a directory name must not be mistaken for an extension.
    CHECK(guessContentType("", "", "/v1.2/resource") == CT_Other);
}
