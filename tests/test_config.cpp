#include "adb/config.hpp"
#include "harness.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace adb;

namespace {

class TempConfig {
public:
    explicit TempConfig(std::string_view contents) {
        dir_ = fs::temp_directory_path() / ("adb-config-test-" + std::to_string(::getpid()) + "-" +
                                             std::to_string(next_++));
        fs::create_directories(dir_);
        path_ = dir_ / "adb.conf";
        std::ofstream(path_) << contents;
    }
    ~TempConfig() {
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }
    const fs::path &path() const { return path_; }
    const fs::path &dir() const { return dir_; }

private:
    inline static unsigned next_ = 0;
    fs::path dir_;
    fs::path path_;
};

} // namespace

TEST(config_applies_supported_values_and_relative_paths) {
    TempConfig file("# personal defaults\n"
                    "listen = 127.0.0.1:9090\n"
                    "filters = lists\n"
                    "custom-rules = custom.txt\n"
                    "rules = extra.txt\n"
                    "ca-dir = certs\n"
                    "state-dir = state\n"
                    "css = no\n"
                    "stealth = true\n");
    RuntimeConfig cfg;
    std::string error;
    CHECK(loadRuntimeConfig(file.path(), cfg, error));
    CHECK_EQ(cfg.proxy.listenAddr, "127.0.0.1");
    CHECK_EQ(cfg.proxy.listenPort, 9090);
    CHECK_EQ(cfg.filtersDir.string(), (file.dir() / "lists").string());
    CHECK_EQ(cfg.customRules.string(), (file.dir() / "custom.txt").string());
    CHECK_EQ(cfg.ruleFiles.size(), 1u);
    CHECK_EQ(cfg.ruleFiles.front().string(), (file.dir() / "extra.txt").string());
    CHECK_EQ(cfg.caDir.string(), (file.dir() / "certs").string());
    CHECK_EQ(cfg.stateDir.string(), (file.dir() / "state").string());
    CHECK(!cfg.proxy.injectCss);
    CHECK(cfg.proxy.stealthHeaders);
}

TEST(config_rejects_unknown_keys_and_invalid_values) {
    TempConfig unknown("typo = value\n");
    RuntimeConfig cfg;
    std::string error;
    CHECK(!loadRuntimeConfig(unknown.path(), cfg, error));
    CHECK(error.find("unknown key 'typo'") != std::string::npos);

    TempConfig invalid("listen = 127.0.0.1\n");
    error.clear();
    CHECK(!loadRuntimeConfig(invalid.path(), cfg, error));
    CHECK(error.find("invalid value for 'listen'") != std::string::npos);
}

TEST(default_config_uses_xdg_directories) {
    const char *oldConfig = std::getenv("XDG_CONFIG_HOME");
    const char *oldData = std::getenv("XDG_DATA_HOME");
    const char *oldState = std::getenv("XDG_STATE_HOME");
    const bool hadConfig = oldConfig != nullptr;
    const bool hadData = oldData != nullptr;
    const bool hadState = oldState != nullptr;
    const std::string savedConfig = oldConfig ? oldConfig : "";
    const std::string savedData = oldData ? oldData : "";
    const std::string savedState = oldState ? oldState : "";

    ::setenv("XDG_CONFIG_HOME", "/tmp/adb-xdg-config", 1);
    ::setenv("XDG_DATA_HOME", "/tmp/adb-xdg-data", 1);
    ::setenv("XDG_STATE_HOME", "/tmp/adb-xdg-state", 1);
    const RuntimeConfig cfg = defaultRuntimeConfig();
    CHECK_EQ(cfg.configFile.string(), "/tmp/adb-xdg-config/adb/adb.conf");
    CHECK_EQ(cfg.customRules.string(), "/tmp/adb-xdg-config/adb/custom.txt");
    CHECK_EQ(cfg.caDir.string(), "/tmp/adb-xdg-config/adb");
    CHECK_EQ(cfg.filtersDir.string(), "/tmp/adb-xdg-data/adb/filters");
    CHECK_EQ(cfg.stateDir.string(), "/tmp/adb-xdg-state/adb");

    if (hadConfig) ::setenv("XDG_CONFIG_HOME", savedConfig.c_str(), 1);
    else ::unsetenv("XDG_CONFIG_HOME");
    if (hadData) ::setenv("XDG_DATA_HOME", savedData.c_str(), 1);
    else ::unsetenv("XDG_DATA_HOME");
    if (hadState) ::setenv("XDG_STATE_HOME", savedState.c_str(), 1);
    else ::unsetenv("XDG_STATE_HOME");
}
