#include "adb/http.hpp"
#include "harness.hpp"

#include <string>

using namespace adb;

TEST(headers_are_case_insensitive) {
    http::Headers h;
    h.append("Content-Type", "text/html");
    CHECK(h.has("content-type"));
    CHECK(h.has("CONTENT-TYPE"));
    CHECK(!h.has("content-length"));
    CHECK_EQ(h.get("cOnTeNt-TyPe"), "text/html");
    CHECK_EQ(h.get("nope"), "");

    h.set("CONTENT-type", "application/json");
    CHECK_EQ(h.items.size(), size_t(1));
    CHECK_EQ(h.get("Content-Type"), "application/json");

    h.append("X-Dup", "a");
    h.append("x-dup", "b");
    CHECK_EQ(h.items.size(), size_t(3));
    h.set("X-DUP", "c"); // collapses duplicates
    CHECK_EQ(h.items.size(), size_t(2));
    CHECK_EQ(h.get("x-dup"), "c");

    h.remove("content-TYPE");
    CHECK(!h.has("Content-Type"));
    CHECK_EQ(h.items.size(), size_t(1));
}

TEST(parse_request_head_complete) {
    const std::string buf = "GET /a?b=1 HTTP/1.1\r\n"
                            "Host: example.com\r\n"
                            "X-Pad:   spaced value \t\r\n"
                            "\r\n"
                            "BODYBYTES";
    http::Request r;
    const long n = http::parseRequestHead(buf, r);
    CHECK_EQ(n, long(buf.size() - 9)); // everything but "BODYBYTES"
    CHECK_EQ(r.method, "GET");
    CHECK_EQ(r.target, "/a?b=1");
    CHECK_EQ(r.version, "HTTP/1.1");
    CHECK_EQ(r.headers.get("host"), "example.com");
    CHECK_EQ(r.headers.get("x-pad"), "spaced value");
    CHECK(r.body.empty());
}

TEST(parse_request_head_truncated_returns_zero) {
    http::Request r;
    CHECK_EQ(http::parseRequestHead("GET / HTTP/1.1\r\nHost: a\r\n", r), 0L);
    CHECK_EQ(http::parseRequestHead("", r), 0L);
    CHECK_EQ(http::parseRequestHead("GET / HTTP/1.1\r\n\r", r), 0L);
}

TEST(parse_request_head_rejects_oversized_and_folded) {
    std::string buf = "GET / HTTP/1.1\r\n";
    for (int i = 0; i < 201; ++i) buf += "X-H" + std::to_string(i) + ": v\r\n";
    buf += "\r\n";
    http::Request r;
    CHECK_EQ(http::parseRequestHead(buf, r), -1L);

    // obs-fold continuation lines are rejected outright
    http::Request r2;
    CHECK_EQ(http::parseRequestHead("GET / HTTP/1.1\r\nHost: a\r\n more\r\n\r\n", r2), -1L);

    // no version -> malformed
    http::Request r3;
    CHECK_EQ(http::parseRequestHead("GET /\r\n\r\n", r3), -1L);
}

TEST(parse_response_head) {
    http::Response resp;
    const std::string buf = "HTTP/1.1 301 Moved Permanently\r\nLocation: /x\r\n\r\n";
    CHECK_EQ(http::parseResponseHead(buf, resp), long(buf.size()));
    CHECK_EQ(resp.status, 301);
    CHECK_EQ(resp.reason, "Moved Permanently");
    CHECK_EQ(resp.headers.get("location"), "/x");

    http::Response bare;
    CHECK(http::parseResponseHead("HTTP/1.1 200\r\n\r\n", bare) > 0);
    CHECK_EQ(bare.status, 200);
    CHECK_EQ(bare.reason, "");
}

TEST(serialize_roundtrip) {
    http::Response r;
    r.status = 204;
    r.reason = "No Content";
    r.headers.set("X-A", "1");
    CHECK_EQ(r.serialize(), "HTTP/1.1 204 No Content\r\nX-A: 1\r\n\r\n");

    http::Request q;
    q.method  = "POST";
    q.target  = "/p";
    q.version = "HTTP/1.1";
    q.headers.set("Content-Length", "2");
    q.body = "hi";
    CHECK_EQ(q.serialize(), "POST /p HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi");
}

TEST(plan_response_body) {
    using K = http::BodyPlan::Kind;

    http::Response r204;
    r204.status = 204;
    r204.headers.set("Content-Length", "10"); // must be ignored
    CHECK(http::planResponseBody(r204, "GET").kind == K::None);

    http::Response r304;
    r304.status = 304;
    CHECK(http::planResponseBody(r304, "GET").kind == K::None);

    http::Response r100;
    r100.status = 100;
    CHECK(http::planResponseBody(r100, "GET").kind == K::None);

    http::Response ok;
    ok.headers.set("Content-Length", "1234");
    CHECK(http::planResponseBody(ok, "HEAD").kind == K::None); // HEAD never has a body
    const http::BodyPlan len = http::planResponseBody(ok, "GET");
    CHECK(len.kind == K::Length);
    CHECK_EQ(len.length, size_t(1234));

    http::Response ch;
    ch.headers.set("Transfer-Encoding", "gzip, Chunked");
    ch.headers.set("Content-Length", "5"); // chunked wins
    CHECK(http::planResponseBody(ch, "GET").kind == K::Chunked);

    http::Response open;
    CHECK(http::planResponseBody(open, "GET").kind == K::UntilClose);

    http::Response tunnelOk;
    CHECK(http::planResponseBody(tunnelOk, "CONNECT").kind == K::None);
}

TEST(plan_request_body) {
    using K = http::BodyPlan::Kind;
    http::Request g;
    CHECK(http::planRequestBody(g).kind == K::None);

    http::Request p;
    p.headers.set("Content-Length", "7");
    const http::BodyPlan bp = http::planRequestBody(p);
    CHECK(bp.kind == K::Length);
    CHECK_EQ(bp.length, size_t(7));

    p.headers.set("Transfer-Encoding", "chunked");
    CHECK(http::planRequestBody(p).kind == K::Chunked);
}

TEST(dechunk_basic) {
    size_t consumed = 0;
    const std::string in = "5\r\nhello\r\n0\r\n\r\n";
    const auto out = http::dechunk(in, consumed);
    CHECK(out.has_value());
    CHECK_EQ(*out, "hello");
    CHECK_EQ(consumed, in.size());
}

TEST(dechunk_extensions_trailers_and_truncation) {
    size_t consumed = 0;
    const std::string in = "3;name=v\r\nabc\r\n2\r\nde\r\n0\r\nX-Trail: 1\r\n\r\nLEFTOVER";
    const auto out = http::dechunk(in, consumed);
    CHECK(out.has_value());
    CHECK_EQ(*out, "abcde");
    CHECK_EQ(consumed, in.size() - 8);

    size_t c2 = 0;
    CHECK(!http::dechunk("5\r\nhel", c2).has_value());          // body short
    CHECK(!http::dechunk("5\r\nhello\r\n", c2).has_value());    // no terminator
    CHECK(!http::dechunk("5\r\nhello\r\n0\r\n", c2).has_value()); // trailer unfinished
    CHECK(!http::dechunk("zz\r\n", c2).has_value());            // bad chunk size
}

TEST(gzip_roundtrip) {
    std::string src;
    for (int i = 0; i < 500; ++i) src += "<div class=\"ad\">buy things</div>\n";

    const auto z = http::gzip(src);
    CHECK(z.has_value());
    CHECK(z->size() >= 2);
    CHECK_EQ(int(uint8_t((*z)[0])), 0x1f); // gzip magic
    CHECK_EQ(int(uint8_t((*z)[1])), 0x8b);
    CHECK(z->size() < src.size());

    const auto back = http::gunzip(*z);
    CHECK(back.has_value());
    CHECK_EQ(*back, src);

    CHECK(!http::gunzip("not compressed at all").has_value());
    const auto empty = http::gunzip("");
    CHECK(empty.has_value());
    CHECK_EQ(*empty, "");
}

TEST(split_host_port) {
    std::string h;
    uint16_t p = 0;

    http::splitHostPort("a.com:443", h, p);
    CHECK_EQ(h, "a.com");
    CHECK_EQ(p, uint16_t(443));

    http::splitHostPort("a.com", h, p);
    CHECK_EQ(h, "a.com");
    CHECK_EQ(p, uint16_t(0));

    http::splitHostPort("[::1]:8080", h, p);
    CHECK_EQ(h, "::1");
    CHECK_EQ(p, uint16_t(8080));

    http::splitHostPort("[2001:db8::1]", h, p);
    CHECK_EQ(h, "2001:db8::1");
    CHECK_EQ(p, uint16_t(0));

    http::splitHostPort("fe80::1", h, p); // bare v6, no port
    CHECK_EQ(h, "fe80::1");
    CHECK_EQ(p, uint16_t(0));
}

TEST(blocked_responses) {
    const http::Response img = http::blockedResponse("image/png,image/webp,*/*");
    CHECK_EQ(img.status, 200);
    CHECK_EQ(img.headers.get("Content-Type"), "image/gif");
    CHECK_EQ(img.body.size(), size_t(43));
    CHECK_EQ(img.body.substr(0, 6), "GIF89a");
    CHECK_EQ(int(uint8_t(img.body.back())), 0x3b);
    CHECK_EQ(img.headers.get("content-length"), "43");
    CHECK_EQ(img.headers.get("Cache-Control"), "no-store");
    CHECK_EQ(img.headers.get("X-Adb-Blocked"), "1");

    const http::Response js = http::blockedResponse("application/javascript");
    CHECK_EQ(js.status, 200);
    CHECK_EQ(js.headers.get("Content-Type"), "application/javascript");
    CHECK(js.body.empty());

    const http::Response doc = http::blockedResponse("text/html");
    CHECK_EQ(doc.status, 204);
    CHECK_EQ(doc.reason, "No Content");
    CHECK(doc.body.empty());
    CHECK(!doc.headers.has("Content-Type"));
    CHECK_EQ(doc.headers.get("X-Adb-Blocked"), "1");

    const http::Response none = http::blockedResponse("");
    CHECK_EQ(none.status, 204);
}
