#pragma once

#include "adb/proxy.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace adb {

struct RuntimeConfig {
    ProxyConfig proxy;
    std::filesystem::path configFile;
    std::filesystem::path filtersDir;
    std::filesystem::path customRules;
    std::filesystem::path caDir;
    std::filesystem::path stateDir;
    std::vector<std::filesystem::path> ruleFiles;
};

// Builds per-user defaults from HOME and the XDG base-directory environment.
RuntimeConfig defaultRuntimeConfig();

// Applies a strict key=value configuration file to cfg. Empty lines and lines
// beginning with '#' are ignored. Relative paths are resolved from the file's
// directory. On failure, cfg may be partially updated and error describes the
// offending line.
bool loadRuntimeConfig(const std::filesystem::path &path, RuntimeConfig &cfg, std::string &error);

} // namespace adb
