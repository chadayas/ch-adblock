#include "adb/config.hpp"

#include "adb/http.hpp"

#include <charconv>
#include <cstdlib>
#include <fstream>
#include <string_view>

namespace adb {
namespace {

namespace fs = std::filesystem;

std::string_view trim(std::string_view value) {
    const size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}

fs::path envPath(const char *name, const fs::path &fallback) {
    const char *value = std::getenv(name);
    return value && *value ? fs::path(value) : fallback;
}

bool parseBool(std::string_view value, bool &out) {
    if (value == "true" || value == "yes" || value == "1") {
        out = true;
        return true;
    }
    if (value == "false" || value == "no" || value == "0") {
        out = false;
        return true;
    }
    return false;
}

bool parseListen(std::string_view value, ProxyConfig &proxy) {
    std::string host;
    uint16_t port = 0;
    http::splitHostPort(value, host, port);
    if (host.empty() || port == 0) return false;
    proxy.listenAddr = std::move(host);
    proxy.listenPort = port;
    return true;
}

fs::path configPath(std::string_view value, const fs::path &base) {
    fs::path path(value);
    return path.is_absolute() ? path : base / path;
}

} // namespace

RuntimeConfig defaultRuntimeConfig() {
    const fs::path home = envPath("HOME", fs::path("."));
    const fs::path configRoot = envPath("XDG_CONFIG_HOME", home / ".config");
    const fs::path dataRoot = envPath("XDG_DATA_HOME", home / ".local" / "share");
    const fs::path stateRoot = envPath("XDG_STATE_HOME", home / ".local" / "state");

    RuntimeConfig cfg;
    cfg.configFile = configRoot / "adb" / "adb.conf";
    cfg.filtersDir = dataRoot / "adb" / "filters";
    cfg.customRules = configRoot / "adb" / "custom.txt";
    cfg.caDir = configRoot / "adb";
    cfg.stateDir = stateRoot / "adb";
    return cfg;
}

bool loadRuntimeConfig(const fs::path &path, RuntimeConfig &cfg, std::string &error) {
    std::ifstream input(path);
    if (!input) {
        error = "cannot open " + path.string();
        return false;
    }

    const fs::path base = path.parent_path();
    std::string line;
    size_t lineNumber = 0;
    while (std::getline(input, line)) {
        ++lineNumber;
        const std::string_view text = trim(line);
        if (text.empty() || text.front() == '#') continue;

        const size_t equals = text.find('=');
        if (equals == std::string_view::npos) {
            error = path.string() + ':' + std::to_string(lineNumber) + ": expected key=value";
            return false;
        }
        const std::string_view key = trim(text.substr(0, equals));
        const std::string_view value = trim(text.substr(equals + 1));
        if (key.empty() || value.empty()) {
            error = path.string() + ':' + std::to_string(lineNumber) + ": empty key or value";
            return false;
        }

        bool valid = true;
        if (key == "listen") {
            valid = parseListen(value, cfg.proxy);
        } else if (key == "filters") {
            cfg.filtersDir = configPath(value, base);
        } else if (key == "custom-rules") {
            cfg.customRules = configPath(value, base);
        } else if (key == "rules") {
            cfg.ruleFiles.push_back(configPath(value, base));
        } else if (key == "ca-dir") {
            cfg.caDir = configPath(value, base);
        } else if (key == "state-dir") {
            cfg.stateDir = configPath(value, base);
        } else if (key == "css") {
            valid = parseBool(value, cfg.proxy.injectCss);
        } else if (key == "stealth") {
            valid = parseBool(value, cfg.proxy.stealthHeaders);
        } else {
            error = path.string() + ':' + std::to_string(lineNumber) + ": unknown key '" +
                    std::string(key) + "'";
            return false;
        }
        if (!valid) {
            error = path.string() + ':' + std::to_string(lineNumber) + ": invalid value for '" +
                    std::string(key) + "'";
            return false;
        }
    }
    if (input.bad()) {
        error = "cannot read " + path.string();
        return false;
    }
    cfg.configFile = path;
    return true;
}

} // namespace adb
