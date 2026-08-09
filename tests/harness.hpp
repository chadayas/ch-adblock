#pragma once
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace t {

struct Case {
    const char *name;
    std::function<void()> fn;
};
inline std::vector<Case> &registry() {
    static std::vector<Case> r;
    return r;
}
inline int &failures() {
    static int f = 0;
    return f;
}
inline const char *&current() {
    static const char *c = "";
    return c;
}
struct Reg {
    Reg(const char *n, std::function<void()> f) { registry().push_back({n, std::move(f)}); }
};

inline void fail(const char *file, int line, const std::string &msg) {
    ++failures();
    std::fprintf(stderr, "  FAIL %s\n    %s:%d  %s\n", current(), file, line, msg.c_str());
}

} // namespace t

#define TEST(name)                                                                                 \
    static void name();                                                                            \
    static ::t::Reg reg_##name(#name, name);                                                       \
    static void name()

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) ::t::fail(__FILE__, __LINE__, "CHECK(" #cond ")");                            \
    } while (0)

#define CHECK_EQ(a, b)                                                                             \
    do {                                                                                           \
        auto &&_a = (a);                                                                           \
        auto &&_b = (b);                                                                           \
        if (!(_a == _b)) {                                                                         \
            std::string m = std::string("CHECK_EQ(" #a ", " #b ")\n      lhs = ");                 \
            m += ::t::show(_a);                                                                    \
            m += "\n      rhs = ";                                                                 \
            m += ::t::show(_b);                                                                    \
            ::t::fail(__FILE__, __LINE__, m);                                                      \
        }                                                                                          \
    } while (0)

namespace t {
inline std::string show(const std::string &s) { return "\"" + s + "\""; }
inline std::string show(std::string_view s) { return "\"" + std::string(s) + "\""; }
inline std::string show(const char *s) { return std::string("\"") + s + "\""; }
inline std::string show(bool b) { return b ? "true" : "false"; }
template <class T> inline std::string show(T v) { return std::to_string(v); }
} // namespace t
