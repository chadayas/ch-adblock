// Standalone benchmark: load the real lists, measure match latency and the
// size of the injected stylesheet. Not part of the default build; see
// bench/README-less note in notes/04-results.md for how it is compiled.
#include "adb/engine.hpp"
#include "adb/log.hpp"
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>

using namespace adb;
using clk = std::chrono::steady_clock;

static const char *kUrls[] = {
    "https://www.learncpp.com/cpp-tutorial/introduction-to-cpp/",
    "https://www.learncpp.com/blog/wp-includes/js/jquery/jquery.min.js?ver=3.6.0",
    "https://www.learncpp.com/blog/wp-content/plugins/learncpp-prism/prism.js?ver=408",
    "https://www.ezojs.com/ezoic/sa.min.js?q=1",
    "https://g.ezoic.net/ezosuigenerisc.js",
    "https://solutions.cdn.optable.co/ezoic/sdk.js",
    "https://securepubads.g.doubleclick.net/tag/js/gpt.js",
    "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
    "https://www.google-analytics.com/analytics.js",
    "https://static.cloudflareinsights.com/beacon.min.js/v4513226",
    "https://secure.gravatar.com/avatar/abc123?s=64",
    "https://fd.cleantalk.org/ct-bot-detector-wrapper.js?ver=6.68",
    "https://www.learncpp.com/blog/wp-content/themes/septera/style.css",
    "https://example.com/images/logo-2024-final.png",
    "https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js",
    "https://www.learncpp.com/favicon.ico",
};
static const ContentType kTypes[] = {
    CT_Document, CT_Script, CT_Script,     CT_Script, CT_Script,     CT_Script,
    CT_Script,   CT_Script, CT_Script,     CT_Script, CT_Image,      CT_Script,
    CT_Stylesheet, CT_Image, CT_Script,    CT_Image,
};
static constexpr size_t kN = sizeof(kUrls) / sizeof(kUrls[0]);

int main(int argc, char **argv) {
    g_log_level = LogLevel::Warn;
    std::string dir = argc > 1 ? argv[1] : "filters";

    Engine e;
    auto t0 = clk::now();
    size_t files = 0;
    for (auto &de : std::filesystem::directory_iterator(dir))
        if (de.path().extension() == ".txt") { e.loadFile(de.path()); ++files; }
    e.finalize();
    auto t1 = clk::now();
    auto load_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    const auto &s = e.stats();
    std::printf("load        : %zu files, %.0f ms\n", files, load_ms);
    std::printf("rules       : %zu total | %zu shortcut | %zu domain | %zu leftover\n",
                s.rulesTotal, s.byShortcut, s.byDomain, s.leftovers);
    std::printf("cosmetic    : %zu rules\n", s.cosmetic);

    for (const char *h : {"www.learncpp.com", "example.com", "cnn.com"}) {
        auto css = e.cosmeticCss(h);
        auto c0 = clk::now();
        for (int i = 0; i < 20; ++i) css = e.cosmeticCss(h);
        auto c1 = clk::now();
        std::printf("css(%-16s): %8zu bytes  %.2f ms\n", h, css.size(),
                    std::chrono::duration<double, std::milli>(c1 - c0).count() / 20);
    }

    // Token-reduced form. Needs a real document; fetch one with
    //   curl -sL https://www.learncpp.com/cpp-tutorial/introduction-to-cpp/ \
    //        -o /tmp/learncpp.html
    if (std::ifstream hf("/tmp/learncpp.html", std::ios::binary); hf) {
        std::ostringstream ss;
        ss << hf.rdbuf();
        const std::string html = ss.str();
        std::printf("document    : %zu bytes\n", html.size());
        for (const char *h : {"www.learncpp.com", "example.com"}) {
            auto css = e.cosmeticCss(h, html);
            auto c0 = clk::now();
            for (int i = 0; i < 20; ++i) css = e.cosmeticCss(h, html);
            auto c1 = clk::now();
            std::printf("css+html(%-11s): %8zu bytes  %.3f ms\n", h, css.size(),
                        std::chrono::duration<double, std::milli>(c1 - c0).count() / 20);
        }
    } else {
        std::printf("document    : /tmp/learncpp.html missing, skipping css+html\n");
    }

    // Build requests once; we are timing match(), not Request construction.
    std::vector<Request> reqs;
    reqs.reserve(kN);
    for (size_t i = 0; i < kN; ++i)
        reqs.push_back(Request::make(kUrls[i], "www.learncpp.com", kTypes[i]));

    for (int warm = 0; warm < 2; ++warm)
        for (auto &r : reqs) (void)e.match(r);

    const int iters = 2000;
    auto m0 = clk::now();
    size_t blocked = 0;
    for (int i = 0; i < iters; ++i)
        for (auto &r : reqs)
            if (e.match(r).blocked) ++blocked;
    auto m1 = clk::now();
    double total_us = std::chrono::duration<double, std::micro>(m1 - m0).count();
    std::printf("match       : %.2f us/req over %d reqs (%zu blocked/pass)\n",
                total_us / (iters * kN), iters * (int)kN, blocked / iters);

    // Per-URL detail so a pathological URL cannot hide in the average.
    std::printf("\nper-URL:\n");
    for (size_t i = 0; i < kN; ++i) {
        auto p0 = clk::now();
        MatchResult r{};
        for (int k = 0; k < 500; ++k) r = e.match(reqs[i]);
        auto p1 = clk::now();
        std::printf("  %7.2f us  %-6s %s\n",
                    std::chrono::duration<double, std::micro>(p1 - p0).count() / 500,
                    r.rule ? (r.blocked ? "BLOCK" : "ALLOW") : "-", kUrls[i]);
    }
    return 0;
}
