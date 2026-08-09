#pragma once
#include <cstdio>
#include <format>
#include <mutex>
#include <string_view>

namespace adb {

enum class LogLevel { Error = 0, Warn = 1, Info = 2, Debug = 3, Trace = 4 };

// Process-wide verbosity. Set once at startup from the CLI.
inline LogLevel g_log_level = LogLevel::Info;

namespace detail {
inline std::mutex g_log_mu;
inline constexpr std::string_view tag(LogLevel l) {
    switch (l) {
    case LogLevel::Error: return "E";
    case LogLevel::Warn:  return "W";
    case LogLevel::Info:  return "I";
    case LogLevel::Debug: return "D";
    default:              return "T";
    }
}
inline void emit(LogLevel l, std::string_view fn, std::string msg) {
    std::lock_guard lk(g_log_mu);
    std::fprintf(stderr, "[%s] %.*s: %.*s\n", tag(l).data(), (int)fn.size(), fn.data(),
                 (int)msg.size(), msg.data());
}
} // namespace detail

// Mirrors AdGuard's own `"{}: " fmt, __func__` convention -- see notes/01.
#define ADB_LOG(lvl, ...)                                                                          \
    do {                                                                                           \
        if (static_cast<int>(lvl) <= static_cast<int>(::adb::g_log_level))                         \
            ::adb::detail::emit(lvl, __func__, std::format(__VA_ARGS__));                          \
    } while (0)

#define ADB_ERR(...)   ADB_LOG(::adb::LogLevel::Error, __VA_ARGS__)
#define ADB_WARN(...)  ADB_LOG(::adb::LogLevel::Warn,  __VA_ARGS__)
#define ADB_INFO(...)  ADB_LOG(::adb::LogLevel::Info,  __VA_ARGS__)
#define ADB_DBG(...)   ADB_LOG(::adb::LogLevel::Debug, __VA_ARGS__)
#define ADB_TRACE(...) ADB_LOG(::adb::LogLevel::Trace, __VA_ARGS__)

} // namespace adb
