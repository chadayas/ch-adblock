#include <algorithm>
#include "adb/ca.hpp"
#include "adb/config.hpp"
#include "adb/engine.hpp"
#include "adb/http.hpp"
#include "adb/log.hpp"
#include "adb/proxy.hpp"
#include "adb/rule.hpp"
#include "adb/url.hpp"

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
using namespace adb;

namespace {

std::atomic<ProxyServer *> g_server{nullptr};

extern "C" void onSignal(int) {
    ProxyServer *s = g_server.load();
    if (s) s->stop();
}

void usage() {
    std::fputs(
        "usage: adb [options]\n"
        "  --listen ADDR[:PORT]   listen address        (default 127.0.0.1:8080)\n"
        "  --config FILE          configuration file    (default $XDG_CONFIG_HOME/adb/adb.conf)\n"
        "  --filters DIR          public filter lists   (default $XDG_DATA_HOME/adb/filters)\n"
        "  --rules FILE           extra filter list, repeatable\n"
        "  --ca-dir DIR           CA storage            (default $XDG_CONFIG_HOME/adb)\n"
        "  --no-css               disable cosmetic CSS injection\n"
        "  --no-stealth           disable stealth header rewriting\n"
        "  -v | -vv               debug / trace logging\n"
        "  --print-ca             print the CA certificate and exit\n"
        "  --test URL             match one URL and exit\n"
        "     --source HOST         document host for third-party checks\n"
        "     --type TYPE           document|subdocument|script|stylesheet|image|\n"
        "                           font|media|xhr|websocket|ping|other\n",
        stderr);
}


bool parseType(std::string_view s, ContentType &out) {
    struct { const char *name; ContentType t; } kMap[] = {
        {"document", CT_Document},         {"subdocument", CT_Subdocument},
        {"script", CT_Script},             {"stylesheet", CT_Stylesheet},
        {"css", CT_Stylesheet},            {"image", CT_Image},
        {"font", CT_Font},                 {"media", CT_Media},
        {"xhr", CT_XmlHttpRequest},        {"xmlhttprequest", CT_XmlHttpRequest},
        {"websocket", CT_WebSocket},       {"ping", CT_Ping},
        {"popup", CT_Popup},               {"other", CT_Other},
    };
    for (const auto &m : kMap)
        if (s == m.name) {
            out = m.t;
            return true;
        }
    return false;
}

void printStats(const EngineStats &s) {
    ADB_INFO("rules: {} total, {} by shortcut, {} by domain, {} leftovers, {} badfilter, "
             "{} cosmetic, {} lines skipped",
             s.rulesTotal, s.byShortcut, s.byDomain, s.leftovers, s.badfilters, s.cosmetic,
             s.linesSkipped);
}

} // namespace

int main(int argc, char **argv) {
    RuntimeConfig runtime = defaultRuntimeConfig();
    bool explicitConfig = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) != "--config") continue;
        if (i + 1 >= argc) {
            std::fputs("adb: --config requires an argument\n", stderr);
            return 2;
        }
        runtime.configFile = argv[++i];
        explicitConfig = true;
    }
    if (explicitConfig || fs::is_regular_file(runtime.configFile)) {
        std::string error;
        if (!loadRuntimeConfig(runtime.configFile, runtime, error)) {
            std::fprintf(stderr, "adb: %s\n", error.c_str());
            return 2;
        }
    }

    ProxyConfig cfg = runtime.proxy;
    fs::path filtersDir = runtime.filtersDir;
    fs::path caDir = runtime.caDir;
    std::vector<std::string> ruleFiles;
    ruleFiles.reserve(runtime.ruleFiles.size() + 1);
    for (const fs::path &path : runtime.ruleFiles) ruleFiles.push_back(path.string());
    std::string testUrl, testSource, testType;
    bool printCa = false, doTest = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&](const char *what) -> const char * {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "adb: %s requires an argument\n", what);
                std::exit(2);
            }
            return argv[++i];
        };

        if (a == "--listen") {
            std::string host;
            uint16_t port = 0;
            http::splitHostPort(value("--listen"), host, port);
            if (!host.empty()) cfg.listenAddr = host;
            if (port) cfg.listenPort = port;
        } else if (a == "--config") {
            value("--config"); // already loaded before applying CLI overrides
        } else if (a == "--filters") {
            filtersDir = value("--filters");
        } else if (a == "--rules") {
            ruleFiles.emplace_back(value("--rules"));
        } else if (a == "--ca-dir") {
            caDir = value("--ca-dir");
        } else if (a == "--no-css") {
            cfg.injectCss = false;
        } else if (a == "--no-stealth") {
            cfg.stealthHeaders = false;
        } else if (a == "-v") {
            g_log_level = LogLevel::Debug;
        } else if (a == "-vv") {
            g_log_level = LogLevel::Trace;
        } else if (a == "--print-ca") {
            printCa = true;
        } else if (a == "--test") {
            testUrl = value("--test");
            doTest  = true;
        } else if (a == "--source") {
            testSource = value("--source");
        } else if (a == "--type") {
            testType = value("--type");
        } else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else {
            std::fprintf(stderr, "adb: unknown option '%s'\n", a.c_str());
            usage();
            return 2;
        }
    }

    // ---- CA ---------------------------------------------------------------
    CertAuthority ca;
    const bool needCa = printCa || !doTest; // --test never touches TLS
    if (needCa && !ca.ensure(caDir)) {
        ADB_ERR("cannot set up the certificate authority in {}", caDir.string());
        return 1;
    }

    if (printCa) {
        std::printf("%s\n", ca.caPath().string().c_str());
        std::fputs(ca.caPem().c_str(), stdout);
        std::fputs("\nImport this file as a trusted certificate authority:\n"
                   "  Firefox : Settings > Privacy & Security > Certificates > View "
                   "Certificates > Authorities > Import (tick \"Trust to identify websites\")\n"
                   "  Chrome  : chrome://certificate-manager > Custom > Installed by you > "
                   "Import\n",
                   stdout);
        return 0;
    }

    // ---- filter lists -----------------------------------------------------
    Engine engine;
    int listId    = 0;
    size_t loaded = 0;
    if (fs::is_directory(filtersDir)) {
        std::vector<fs::path> files;
        for (const auto &e : fs::directory_iterator(filtersDir))
            if (e.is_regular_file() && e.path().extension() == ".txt") files.push_back(e.path());
        std::sort(files.begin(), files.end());
        for (const auto &p : files) {
            const size_t n = engine.loadFile(p, listId++);
            ADB_INFO("{}: {} rules", p.filename().string(), n);
            loaded += n;
        }
    } else if (ruleFiles.empty() && !fs::is_regular_file(runtime.customRules)) {
        ADB_WARN("no filter directory or rule files found at configured XDG paths");
    }
    if (fs::is_regular_file(runtime.customRules)) {
        const size_t n = engine.loadFile(runtime.customRules, listId++);
        ADB_INFO("{}: {} rules", runtime.customRules.filename().string(), n);
        loaded += n;
    }
    for (const std::string &f : ruleFiles) {
        const size_t n = engine.loadFile(f, listId++);
        ADB_INFO("{}: {} rules", f, n);
        loaded += n;
    }
    engine.finalize();
    ADB_INFO("loaded {} rules from {} list(s)", loaded, listId);
    printStats(engine.stats());

    // ---- one-shot match ---------------------------------------------------
    if (doTest) {
        const url::Parts p = url::split(testUrl);
        if (!p.valid) {
            std::fprintf(stderr, "adb: cannot parse URL '%s'\n", testUrl.c_str());
            return 2;
        }
        ContentType t = guessContentType({}, {}, p.path);
        if (!testType.empty() && !parseType(testType, t)) {
            std::fprintf(stderr, "adb: unknown --type '%s'\n", testType.c_str());
            return 2;
        }
        const Request req      = Request::make(testUrl, testSource, t);
        const MatchResult m    = engine.match(req);
        if (m.blocked)
            std::printf("BLOCK %s by %s\n", testUrl.c_str(), m.rule->text.c_str());
        else if (m.rule)
            std::printf("ALLOW %s by %s\n", testUrl.c_str(), m.rule->text.c_str());
        else
            std::printf("ALLOW %s\n", testUrl.c_str());

        const std::string css = engine.cosmeticCss(req.host);
        if (!css.empty())
            std::fprintf(stderr, "cosmetic: %zu bytes of CSS for %s\n", css.size(),
                         req.host.c_str());
        return 0;
    }

    // ---- proxy ------------------------------------------------------------
    ProxyServer server(cfg, engine, ca);
    g_server.store(&server);
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    ADB_INFO("proxy on {}:{}, CA {}", cfg.listenAddr, cfg.listenPort, ca.caPath().string());
    const bool ok = server.run();
    g_server.store(nullptr);

    const ProxyStats &st = server.stats();
    ADB_INFO("{} connections, {} requests, {} blocked, {} injected, {} tunnelled",
             st.connections.load(), st.requests.load(), st.blocked.load(), st.cssInjected.load(),
             st.tunneled.load());
    return ok ? 0 : 1;
}
