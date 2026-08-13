#include "adb/engine.hpp"

#include "adb/log.hpp"
#include "adb/parser.hpp"
#include "adb/url.hpp"

#include <algorithm>
#include <cstring>
#include <deque>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <vector>

namespace adb {
namespace {

constexpr std::string_view kSpace = " \t\r\n";

std::string_view trim(std::string_view s) {
    const size_t b = s.find_first_not_of(kSpace);
    if (b == std::string_view::npos) return {};
    return s.substr(b, s.find_last_not_of(kSpace) - b + 1);
}

// Heterogeneous hashing so match() can probe the tables with a string_view
// window over the URL -- no per-probe std::string allocation.
struct SvHash {
    using is_transparent = void;
    size_t operator()(std::string_view s) const noexcept {
        return std::hash<std::string_view>{}(s);
    }
};
struct SvEq {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const noexcept { return a == b; }
};
using RuleTable = std::unordered_map<std::string, std::vector<const Rule *>, SvHash, SvEq>;

// ---------------------------------------------------------------------------
// Shortcut index.
//
// Same role as AdGuard's `rules_by_shortcut` (notes/02 section 4). We cannot
// afford a real Aho-Corasick automaton over 280 000 literals, so we index on a
// fixed-length gram and slide a window over the URL.
//
// The naive version -- key on the FIRST gram of the shortcut -- is what makes
// this table useless: tens of thousands of rules start with "http", "/ads",
// ".com", so a single probe drags in a bucket of thousands and every one of
// them pays a full substring search. Measured 1.2 ms per request.
//
// Instead we index each rule under its RAREST gram. Correctness is unaffected:
// if the shortcut occurs in the URL then *every* gram of the shortcut occurs in
// the URL, so the chosen one does too. No false negatives, and buckets collapse
// to a handful of rules.
//
// Two further wins fall out of it:
//   * the gram is 4 bytes, so we pack it into a uint32_t and hash an integer
//     instead of a string;
//   * we remember where the gram sits inside the shortcut, so verification is
//     one memcmp at a known offset rather than a scan of the whole URL.
// ---------------------------------------------------------------------------
constexpr size_t kGram = 4;

struct Cand {
    const Rule *rule;
    uint32_t off; // offset of the indexed gram within rule->shortcut
};
using GramTable = std::unordered_map<uint32_t, std::vector<Cand>>;

inline uint32_t packGram(const char *p) {
    uint32_t g;
    std::memcpy(&g, p, kGram);
    return g;
}

// 3-byte key for the short-shortcut table; the top byte stays zero. It lives in
// its own map, so it can never collide with a packed 4-gram.
inline uint32_t packGram3(const char *p) {
    uint32_t g = 0;
    std::memcpy(&g, p, 3);
    return g;
}

// Same `$` scan as the parser: last unescaped `$` outside a /regex/ body and
// not part of `$$`.
size_t findModifierSep(std::string_view p) {
    size_t scanFrom = 0;
    if (p.size() >= 2 && p.front() == '/') {
        for (size_t i = p.size(); i-- > 1;) {
            if (p[i] == '/' && (i + 1 == p.size() || p[i + 1] == '$')) {
                scanFrom = i + 1;
                break;
            }
        }
    }
    for (size_t i = p.size(); i-- > scanFrom;) {
        if (p[i] != '$') continue;
        if (i > 0 && p[i - 1] == '\\') continue;
        if (i > 0 && p[i - 1] == '$') continue;
        if (i + 1 < p.size() && p[i + 1] == '$') continue;
        return i;
    }
    return std::string_view::npos;
}

// `||x^$script,badfilter` -> `||x^$script`;  `||x^$badfilter` -> `||x^`.
// Two rules are the same rule iff their normalised texts are equal.
std::string stripBadfilter(std::string_view text) {
    const std::string_view line = trim(text);
    const size_t sep            = findModifierSep(line);
    if (sep == std::string_view::npos) return std::string(line);

    std::string out(line.substr(0, sep));
    const std::string_view mods = line.substr(sep + 1);
    bool first                  = true;
    size_t start                = 0;
    for (size_t i = 0; i <= mods.size(); ++i) {
        if (i < mods.size()) {
            if (mods[i] == '\\') {
                ++i;
                continue;
            }
            if (mods[i] != ',') continue;
        }
        const std::string_view tok = trim(mods.substr(start, i - start));
        start                      = i + 1;
        if (tok.empty() || tok == "badfilter") continue;
        out.push_back(first ? '$' : ',');
        out.append(tok);
        first = false;
    }
    return out;
}

int priority(const Rule *r) {
    if (r->isImportant) return r->isException ? 4 : 3;
    return r->isException ? 2 : 1;
}

} // namespace

// ===========================================================================
// Engine::Impl
// ===========================================================================

struct Engine::Impl {
    std::deque<Rule> storage_; // stable addresses: match() hands out `const Rule*`
    GramTable byShortcut_;  // rarest 4-gram -> candidates (shortcut >= 4)
    GramTable byShortcut3_; // exact 3-byte shortcut -> candidates
    RuleTable byDomain_;                       // $domain value -> rules
    std::vector<const Rule *> leftovers_;      // unindexable, linear scan
    std::vector<Rule> badfilters_;
    bool finalized_  = false;
    uint32_t nextId_ = 0;
};

Engine::Engine() : impl_(std::make_unique<Impl>()) {}
Engine::~Engine()                            = default;
Engine::Engine(Engine &&) noexcept            = default;
Engine &Engine::operator=(Engine &&) noexcept = default;

// ===========================================================================
// Loading
// ===========================================================================

bool Engine::addLine(std::string_view line, int listId) {
    impl_->finalized_ = false;

    switch (classify(line)) {
    case LineKind::Empty:
        return false;
    case LineKind::Cosmetic:
        if (cosmetic_.addRule(line)) {
            ++stats_.cosmetic;
            return true;
        }
        ++stats_.linesSkipped;
        return false;
    default:
        break;
    }

    std::optional<Rule> r = parseNetworkRule(line);
    if (!r) {
        ++stats_.linesSkipped;
        return false;
    }
    r->listId = listId;
    r->id     = ++impl_->nextId_;

    if (r->isBadfilter) {
        impl_->badfilters_.push_back(std::move(*r));
        ++stats_.badfilters;
        return true;
    }
    impl_->storage_.push_back(std::move(*r));
    ++stats_.rulesTotal;
    return true;
}

size_t Engine::loadFile(const std::filesystem::path &p, int listId) {
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        ADB_ERR("cannot open filter list {}", p.string());
        return 0;
    }
    size_t accepted = 0;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (addLine(line, listId)) ++accepted;
    }
    ADB_INFO("loaded {} rules from {}", accepted, p.string());
    return accepted;
}

void Engine::finalize() {
    if (impl_->finalized_) return;

    // 1. $badfilter is a post-filter: it disables another rule by text match.
    std::unordered_set<std::string> disabled;
    disabled.reserve(impl_->badfilters_.size() * 2);
    for (const Rule &bf : impl_->badfilters_) disabled.insert(stripBadfilter(bf.text));

    impl_->byShortcut_.clear();
    impl_->byShortcut3_.clear();
    impl_->byDomain_.clear();
    impl_->leftovers_.clear();

    // 2. Collect the survivors, splitting them across the three tables. Rules
    //    that will live in the shortcut table are parked first: choosing their
    //    gram needs the global frequency table, which only exists once every
    //    survivor has been seen.
    std::vector<const Rule *> shortcutRules;
    shortcutRules.reserve(impl_->storage_.size());
    std::unordered_map<uint32_t, uint32_t> gramFreq;
    gramFreq.reserve(impl_->storage_.size());

    size_t survivors = 0;
    for (const Rule &r : impl_->storage_) {
        if (!disabled.empty() && disabled.count(stripBadfilter(r.text))) {
            ADB_DBG("Rule is disabled by $badfilter: {}", r.text);
            continue;
        }
        ++survivors;

        if (r.shortcut.size() >= kGram) {
            shortcutRules.push_back(&r);
            const size_t n = r.shortcut.size() - kGram;
            for (size_t i = 0; i <= n; ++i) ++gramFreq[packGram(r.shortcut.data() + i)];
        } else if (r.shortcut.size() == 3) {
            // The parser's floor is 3, so this is the only short case. Probing a
            // 3-byte window costs one extra sweep of the URL and removes ~900
            // rules from the every-request linear scan.
            impl_->byShortcut3_[packGram3(r.shortcut.data())].push_back(Cand{&r, 0});
        } else if (!r.shortcut.empty()) {
            impl_->leftovers_.push_back(&r);
        } else if (!r.includeDomains.empty()) {
            for (const std::string &d : r.includeDomains) impl_->byDomain_[d].push_back(&r);
        } else {
            impl_->leftovers_.push_back(&r);
        }
    }

    // 3. Second pass: every rule goes under the rarest gram it contains.
    for (const Rule *r : shortcutRules) {
        const size_t n = r->shortcut.size() - kGram;
        uint32_t bestGram = packGram(r->shortcut.data());
        uint32_t bestOff  = 0;
        uint32_t bestFreq = gramFreq[bestGram];
        for (size_t i = 1; i <= n && bestFreq > 1; ++i) {
            const uint32_t g = packGram(r->shortcut.data() + i);
            const uint32_t f = gramFreq[g];
            if (f < bestFreq) {
                bestFreq = f;
                bestGram = g;
                bestOff  = static_cast<uint32_t>(i);
            }
        }
        impl_->byShortcut_[bestGram].push_back(Cand{r, bestOff});
    }

    // 4. Stats.
    stats_.rulesTotal = survivors;
    stats_.byShortcut = shortcutRules.size();
    for (const auto &kv : impl_->byShortcut3_) stats_.byShortcut += kv.second.size();
    stats_.byDomain   = 0;
    for (const auto &kv : impl_->byDomain_) stats_.byDomain += kv.second.size();
    stats_.leftovers  = impl_->leftovers_.size();
    stats_.badfilters = impl_->badfilters_.size();

    impl_->finalized_ = true;
    cosmetic_.finalize();

    size_t worst = 0;
    for (const auto &kv : impl_->byShortcut_) worst = std::max(worst, kv.second.size());
    size_t worst3 = 0;
    for (const auto &kv : impl_->byShortcut3_) worst3 = std::max(worst3, kv.second.size());
    ADB_INFO("finalized: {} rules ({} by shortcut, {} by domain, {} leftovers), {} cosmetic",
             stats_.rulesTotal, stats_.byShortcut, stats_.byDomain, stats_.leftovers,
             stats_.cosmetic);
    ADB_DBG("shortcut index: {} 4-grams (worst {}), {} 3-grams (worst {})",
            impl_->byShortcut_.size(), worst, impl_->byShortcut3_.size(), worst3);
}

// ===========================================================================
// Matching
// ===========================================================================

MatchResult Engine::match(const Request &req) const {
    const Rule *best = nullptr;
    int bestPrio     = 0;

    // Checks run cheapest-first, in the exact order recovered from the binary
    // (notes/02 section 5). Trace phrasing mirrors the original log strings.
    auto consider = [&](const Rule *r, bool shortcutVerified) {
        ADB_TRACE("-> examining rule {}", r->text);

        if (!shortcutVerified && !r->shortcut.empty() &&
            req.url.find(r->shortcut) == std::string::npos) {
            ADB_TRACE("...url doesn't contain shortcut ({})", r->shortcut);
            return;
        }
        if ((r->thirdParty == ThirdParty::Only && !req.thirdParty) ||
            (r->thirdParty == ThirdParty::NotOnly && req.thirdParty)) {
            ADB_TRACE("...thirdparty check failed");
            return;
        }
        const auto type = static_cast<uint32_t>(req.type);
        if (!((r->typesAllow == 0 || (r->typesAllow & type)) && !(r->typesDeny & type))) {
            ADB_TRACE("...request type check failed");
            return;
        }
        const auto method = static_cast<uint16_t>(req.method);
        if (!((r->methods == 0 || (r->methods & method)) && !(r->methodsDeny & method))) {
            ADB_TRACE("...request method check failed");
            return;
        }
        for (const std::string &d : r->denyAllow) {
            if (url::isSubdomainOf(req.host, d)) {
                ADB_TRACE("...denyallow check failed");
                return;
            }
        }
        if (!r->includeDomains.empty() || !r->excludeDomains.empty()) {
            const std::string_view src = req.sourceHost.empty() ? std::string_view(req.host)
                                                                : std::string_view(req.sourceHost);
            for (const std::string &d : r->excludeDomains) {
                if (url::isSubdomainOf(src, d)) {
                    ADB_TRACE("...domain check failed");
                    return;
                }
            }
            if (!r->includeDomains.empty()) {
                bool hit = false;
                for (const std::string &d : r->includeDomains) {
                    if (url::isSubdomainOf(src, d)) {
                        hit = true;
                        break;
                    }
                }
                if (!hit) {
                    ADB_TRACE("...domain check failed");
                    return;
                }
            }
        }
        if (!r->matchesPattern(req.url, req.hostStart, req.hostEnd)) {
            ADB_TRACE("...url was not matched against rule pattern");
            return;
        }

        const int p = priority(r);
        if (p > bestPrio) {
            bestPrio = p;
            best     = r;
        }
        ADB_TRACE("URL '{}' matched rule '{}'!", req.url, r->text);
    };

    // --- shortcuts table --------------------------------------------------
    // Slide a 4-byte window over the URL, probe the gram table, and verify the
    // full shortcut at the offset the index already knows -- one memcmp, not a
    // search. Reaching the same rule from two positions is possible but rare
    // and harmless: `consider` is idempotent.
    const std::string_view u(req.url);
    size_t found = 0;
    if (u.size() >= kGram) {
        const char *base = u.data();
        for (size_t i = 0, n = u.size() - kGram; i <= n; ++i) {
            const auto it = impl_->byShortcut_.find(packGram(base + i));
            if (it == impl_->byShortcut_.end()) continue;
            found += it->second.size();
            for (const Cand &c : it->second) {
                const std::string &sc = c.rule->shortcut;
                if (i < c.off) continue;
                const size_t start = i - c.off;
                if (start + sc.size() > u.size()) continue;
                if (std::memcmp(base + start, sc.data(), sc.size()) != 0) continue;
                consider(c.rule, true);
            }
        }
    }
    // Second sweep for the 3-byte shortcuts. The window IS the whole shortcut,
    // so a hit needs no further verification.
    if (!impl_->byShortcut3_.empty() && u.size() >= 3) {
        const char *base = u.data();
        for (size_t i = 0, n = u.size() - 3; i <= n; ++i) {
            const auto it = impl_->byShortcut3_.find(packGram3(base + i));
            if (it == impl_->byShortcut3_.end()) continue;
            found += it->second.size();
            for (const Cand &c : it->second) consider(c.rule, true);
        }
    }
    ADB_TRACE("...shortcuts table found {} rules", found);

    // --- domains table ----------------------------------------------------
    // Walk the host and each parent domain: a.b.example.com -> b.example.com
    // -> example.com -> com.
    if (!impl_->byDomain_.empty()) {
        const std::string_view src =
            req.sourceHost.empty() ? std::string_view(req.host) : std::string_view(req.sourceHost);
        for (std::string_view h = src; !h.empty();) {
            const auto it = impl_->byDomain_.find(h);
            if (it != impl_->byDomain_.end()) {
                if (it->second.empty())
                    ADB_WARN("SHOULD NOT HAPPEN: url '{}' -- empty value for rules_by_domain "
                             "table!",
                             req.url);
                ADB_TRACE("...domains table found {} rules for {}", it->second.size(), h);
                for (const Rule *r : it->second) consider(r, false);
            }
            const size_t dot = h.find('.');
            if (dot == std::string_view::npos) break;
            h = h.substr(dot + 1);
        }
    }

    // --- leftovers --------------------------------------------------------
    ADB_TRACE("...leftovers table found {} rules", impl_->leftovers_.size());
    for (const Rule *r : impl_->leftovers_) consider(r, false);

    return MatchResult{best, best != nullptr && !best->isException};
}

// ===========================================================================
// Content-type inference
// ===========================================================================

ContentType guessContentType(std::string_view secFetchDest, std::string_view accept,
                             std::string_view path) {
    if (!secFetchDest.empty()) {
        const std::string d = url::lower(trim(secFetchDest));
        if (d == "document") return CT_Document;
        if (d == "iframe" || d == "frame") return CT_Subdocument;
        if (d == "script" || d == "worker" || d == "serviceworker" || d == "sharedworker")
            return CT_Script;
        if (d == "style") return CT_Stylesheet;
        if (d == "image") return CT_Image;
        if (d == "font") return CT_Font;
        if (d == "audio" || d == "video" || d == "track") return CT_Media;
        if (d == "empty") return CT_XmlHttpRequest;
        if (d == "websocket") return CT_WebSocket;
    }

    if (!accept.empty()) {
        const std::string a = url::lower(accept);
        if (a.find("text/html") != std::string::npos) return CT_Document;
        if (a.find("text/css") != std::string::npos) return CT_Stylesheet;
        if (a.find("image/") != std::string::npos) return CT_Image;
        if (a.find("application/javascript") != std::string::npos ||
            a.find("text/javascript") != std::string::npos)
            return CT_Script;
    }

    std::string_view p = path;
    if (const size_t q = p.find('?'); q != std::string_view::npos) p = p.substr(0, q);
    const size_t slash = p.rfind('/');
    const std::string_view file = (slash == std::string_view::npos) ? p : p.substr(slash + 1);
    const size_t dot            = file.rfind('.');
    if (dot != std::string_view::npos) {
        const std::string ext = url::lower(file.substr(dot));
        struct ExtType {
            std::string_view e;
            ContentType t;
        };
        static constexpr ExtType kExt[] = {
            {".js", CT_Script},    {".mjs", CT_Script},   {".css", CT_Stylesheet},
            {".png", CT_Image},    {".jpg", CT_Image},    {".jpeg", CT_Image},
            {".gif", CT_Image},    {".webp", CT_Image},   {".svg", CT_Image},
            {".ico", CT_Image},    {".avif", CT_Image},   {".woff", CT_Font},
            {".woff2", CT_Font},   {".ttf", CT_Font},     {".otf", CT_Font},
            {".eot", CT_Font},     {".mp4", CT_Media},    {".webm", CT_Media},
            {".mp3", CT_Media},    {".m4a", CT_Media},    {".ogg", CT_Media},
            {".m3u8", CT_Media},   {".html", CT_Document}, {".htm", CT_Document},
        };
        for (const ExtType &x : kExt)
            if (x.e == ext) return x.t;
    }
    return CT_Other;
}

} // namespace adb
