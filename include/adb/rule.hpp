#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace adb {

// ---------------------------------------------------------------------------
// Content types -- a bitmask, exactly like the engine we studied. The whole
// point is that `$script,image` narrowing is a single AND, tested long before
// any string work. See notes/02 section 5.
// ---------------------------------------------------------------------------
enum ContentType : uint32_t {
    CT_None           = 0,
    CT_Document       = 1u << 0,
    CT_Subdocument    = 1u << 1,
    CT_Script         = 1u << 2,
    CT_Stylesheet     = 1u << 3,
    CT_Image          = 1u << 4,
    CT_Font           = 1u << 5,
    CT_Media          = 1u << 6,
    CT_XmlHttpRequest = 1u << 7,
    CT_WebSocket      = 1u << 8,
    CT_Ping           = 1u << 9,
    CT_Other          = 1u << 10,
    CT_Popup          = 1u << 11,
    CT_All            = 0x0FFFu,
};

enum class ThirdParty : uint8_t { Any, Only, NotOnly };

// HTTP methods as a bitmask for `$method=get|post`.
enum Method : uint16_t {
    M_None    = 0,
    M_GET     = 1u << 0,
    M_POST    = 1u << 1,
    M_PUT     = 1u << 2,
    M_DELETE  = 1u << 3,
    M_HEAD    = 1u << 4,
    M_OPTIONS = 1u << 5,
    M_PATCH   = 1u << 6,
    M_CONNECT = 1u << 7,
    M_TRACE   = 1u << 8,
    M_All     = 0x01FFu,
};

Method methodFromString(std::string_view s); // M_None if unknown

class Regex; // opaque PCRE2 wrapper, defined in parser.cpp

// ---------------------------------------------------------------------------
// A single network rule.
// ---------------------------------------------------------------------------
struct Rule {
    std::string text;    // original line, for $badfilter and debugging
    std::string pattern; // pattern body, anchors stripped, lowercased unless matchCase

    // Longest literal run in `pattern`; empty => rule lands in `leftovers`.
    std::string shortcut;

    // $domain= / $from= (include) and their ~negated form (exclude).
    std::vector<std::string> includeDomains;
    std::vector<std::string> excludeDomains;
    // $denyallow= -- request domains the rule must NOT apply to.
    std::vector<std::string> denyAllow;

    uint32_t typesAllow = 0; // 0 => all types
    uint32_t typesDeny  = 0;
    uint16_t methods    = 0; // 0 => all methods
    uint16_t methodsDeny = 0;

    ThirdParty thirdParty = ThirdParty::Any;

    bool isException  = false; // @@
    bool isImportant  = false; // $important
    bool isBadfilter  = false; // $badfilter
    bool isRegex      = false; // /.../
    bool matchCase    = false; // $match-case
    bool domainAnchor = false; // ||
    bool anchorStart  = false; // leading |
    bool anchorEnd    = false; // trailing |

    // $removeparam=foo  (empty vector => modifier absent)
    std::vector<std::string> removeParams;
    bool removeAllParams = false; // bare $removeparam

    std::shared_ptr<Regex> re; // compiled iff isRegex

    uint32_t id = 0;
    int listId  = 0;

    // Does this rule's own pattern/anchors match `url`? Assumes all cheap
    // checks already passed. `url` is lowercased unless matchCase.
    //
    // The three-argument form takes the URL's host span, which `||` rules need.
    // Locating it costs three passes over the URL, and match() tries thousands
    // of candidates against one URL, so the caller computes it once and hands
    // it down. The one-argument form recomputes it and exists for tests.
    bool matchesPattern(std::string_view url, size_t hostStart, size_t hostEnd) const;
    bool matchesPattern(std::string_view url) const;
};

// ---------------------------------------------------------------------------
// One request under test.
// ---------------------------------------------------------------------------
struct Request {
    std::string url;        // full absolute URL, lowercased for matching
    std::string host;       // lowercase, no port
    std::string sourceHost; // document host; empty for top-level navigation
    ContentType type   = CT_Other;
    Method method      = M_GET;
    bool thirdParty    = false;
    // Byte offsets of the host inside `url`; filled by make().
    uint32_t hostStart = 0;
    uint32_t hostEnd   = 0;

    Request() = default;
    // Fills host / thirdParty from `u` and `srcHost`.
    static Request make(std::string_view u, std::string_view srcHost, ContentType t,
                        Method m = M_GET);
};

} // namespace adb
