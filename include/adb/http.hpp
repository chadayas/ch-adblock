#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace adb::http {

struct Header {
    std::string name;  // as received
    std::string value;
};

struct Headers {
    std::vector<Header> items;

    // Case-insensitive lookup. Returns empty view when absent.
    std::string_view get(std::string_view name) const;
    bool has(std::string_view name) const;
    void set(std::string_view name, std::string_view value); // replaces or appends
    void remove(std::string_view name);
    void append(std::string_view name, std::string_view value);
};

struct Request {
    std::string method;
    std::string target; // origin-form "/a?b" or absolute-form "http://h/a"
    std::string version; // "HTTP/1.1"
    Headers headers;
    std::string body;

    std::string serialize() const;
};

struct Response {
    std::string version = "HTTP/1.1";
    int status = 200;
    std::string reason = "OK";
    Headers headers;
    std::string body;

    std::string serialize() const;
};

// Parses request/status line + headers from `buf`.
// Returns the number of bytes consumed (i.e. the header block length incl. the
// final CRLFCRLF), or 0 when the block is incomplete, or -1 on malformed input.
long parseRequestHead(std::string_view buf, Request &out);
long parseResponseHead(std::string_view buf, Response &out);

// Body framing derived from headers.
struct BodyPlan {
    enum class Kind { None, Length, Chunked, UntilClose } kind = Kind::None;
    size_t length = 0; // valid when kind == Length
};
BodyPlan planRequestBody(const Request &r);
BodyPlan planResponseBody(const Response &r, std::string_view requestMethod);

// Decodes a chunked body. Returns nullopt if `buf` does not yet hold the
// terminating zero-length chunk. On success `consumed` gets the byte count.
std::optional<std::string> dechunk(std::string_view buf, size_t &consumed);

// gzip/deflate helpers (zlib). Return nullopt on failure.
std::optional<std::string> gunzip(std::string_view in);
std::optional<std::string> gzip(std::string_view in);

// Splits "host:port"; port 0 when absent.
void splitHostPort(std::string_view hp, std::string &host, uint16_t &port);

// Canned responses.
Response blockedResponse(std::string_view contentTypeHint);

} // namespace adb::http
