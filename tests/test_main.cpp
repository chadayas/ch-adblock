#include "harness.hpp"
#include <cstdio>

int main() {
    int run = 0;
    for (auto &c : t::registry()) {
        t::current() = c.name;
        int before = t::failures();
        c.fn();
        ++run;
        if (t::failures() == before) std::fprintf(stderr, "  ok   %s\n", c.name);
    }
    std::fprintf(stderr, "\n%d tests, %d failures\n", run, t::failures());
    return t::failures() == 0 ? 0 : 1;
}
