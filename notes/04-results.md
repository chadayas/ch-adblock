# Writeup 4 — Does it work?

Measured, not asserted. Everything below is reproducible with the commands shown.

---

## 1. The A/B

Same Chrome instance, same page, cache cleared before each load, **only the
blocker toggled**. The "off" arm still goes through our proxy (so TLS
interception, header rewriting and HTTP re-framing are identical) — it just runs
with an empty filter directory and `--no-css`. That isolates exactly one
variable: the filter engine.

```bash
# off
./build/adb --listen 127.0.0.1:18080 --filters /tmp/emptyfilters --ca-dir /tmp/adbca --no-css
# on
./build/adb --listen 127.0.0.1:18080 --filters filters --ca-dir /tmp/adbca
```

Page: `https://www.learncpp.com/cpp-tutorial/introduction-to-cpp-development/`

| metric | blocking off | blocking on | change |
|---|---:|---:|---:|
| ad / tracker requests | 61 | 19 | −69 % |
| **bytes from ad hosts** | **292 321** | **0** | **−100 %** |
| total requests | 250 | 90 | −64 % |
| **total bytes** | **2 231 964** | **502 329** | **−77 %** |
| visible ad iframes | 5 | 0 | — |
| visible ad placeholders | 1 | 0 | — |
| document height | 8 702 px | 6 403 px | −26 % |
| article text | 8 100 chars | 7 934 chars | intact |

The 19 remaining "ad requests" are requests the browser *attempted*; every one
was answered locally with `204 No Content` and `X-Adb-Blocked: 1`, transferring
zero bytes. They show up in `performance.getEntriesByType('resource')` because
the entry is created when the fetch starts, not when it succeeds.

> One honest gotcha found while measuring: an early run showed one blocked URL
> with `decodedBodySize: 120340`. Its `transferSize` was **0** — Chrome had
> served `gpt.js` from disk cache, populated by the previous unblocked run.
> Clearing the cache made it vanish. Always check `transferSize`, not
> `decodedBodySize`, when you are proving a network block.

### Visually

Blocking off: a Honda display ad above the article and a four-tile video
carousel below it, with the tutorial's own step diagram pushed to the right.

Blocking on: the step diagram sits where it belongs, the ad slot is gone
(not blank — *collapsed*, because we hide the `div.cf_monitor` wrapper, not just
the placeholder `<span>`), and the whole article is intact including the Prism
syntax highlighting.

---

## 2. Subresource sweep

Every URL referenced by the page, fetched through the proxy:

```
77 subresources: 12 BLOCKED, 65 allowed — zero false positives
```

Blocked (all `204`):

```
cmp.gatekeeperconsent.com/min.js            consent-management platform
g.ezoic.net/porpoiseant/qubit.js            Ezoic
g.ezoic.net/privacy/learncpp.com            Ezoic
go.ezodn.com/hb/dall.js                     header bidding
go.ezodn.com/detroitchicago/x.js            Ezoic
na.edge.optable.co                          identity graph
solutions.cdn.optable.co/ezoic/sdk.js       identity graph
pagead2.googlesyndication.com/…/adsbygoogle.js
securepubads.g.doubleclick.net/tag/js/gpt.js
www.ezojs.com/ezoic/sa.min.js               the Ezoic loader
www.googletagmanager.com/gtag/js
```

Allowed: all 65 first-party assets — jQuery, Prism (`prism.js`, 23 018 B),
wpDiscuz, the theme CSS, images, `wp-json` endpoints. Nothing of the site broke.

Note that most of those blocks came from the **public AdGuard lists**, not from
rules I wrote. `gatekeeperconsent`, `porpoiseant`, `hb/dall.js` were not on my
radar; the lists knew about them. That is the actual value of the ecosystem —
the engine is the easy half.

---

## 3. Where the hand-written rules were needed

The public lists carry `||ezojs.com/ezoic/`, which kills the loader. They carry
**no generic cosmetic rule** for Ezoic's placeholder markup — only per-domain
ones (`providr.com`, `medindia.net`, …) that target
`div[id^="ezoic-pub-ad-placeholder-"]`. learncpp emits a **`span`**.

Structure verified on the live page:

```html
<div class="code-block code-block-4" style="margin:8px 0;clear:both">
  <div class="cf_monitor">
    <span id="ezoic-pub-ad-placeholder-124"></span>
    <span data-ez-ph-id="124"></span>
  </div>
</div>
```

Hiding only the placeholder leaves the wrapper's margins as a visible gap, so
`filters/custom.txt` collapses the wrappers too:

```
##span[id^="ezoic-pub-ad-placeholder-"]
##span[data-ez-ph-id]
learncpp.com##div.cf_monitor
learncpp.com##div.code-block
```

Safety check before shipping that: all 6 `div.code-block` elements on the page
wrap an ad slot, and the actual C++ samples use Prism's
`<pre class="language-cpp">`, which no rule touches. Confirmed after the fact —
`articleChars` is unchanged and the highlighted code renders.

---

## 4. Filter-list coverage

Loaded: AdGuard Base (2), Tracking Protection (3), Annoyances (14), plus
`custom.txt`. **388 262 lines.**

```
279 835 network rules accepted
        279 706 indexed by shortcut
          1 016 indexed by $domain
             45 leftovers (linear scan)
            102 $badfilter removals applied
108 300 cosmetic rules
  6 044 lines skipped (unsupported modifier)
```

Independently, counting modifier usage across the raw lists:

```
285 452 network rules, 5 492 rejected for an unsupported modifier  ->  98.1 % accepted
```

The 1.9 % we reject use `$stealth`, `$cookie`, `$redirect`, `$replace`,
`$generichide`, `$app`, `$jsinject` and friends. **Rejecting is deliberate**: a
rule whose modifier changes its meaning must not be applied with that modifier
ignored, or you silently over- or under-block. Cosmetic masks we do not
implement (`#%#` scriptlets 10 753, `#$#` CSS-injection 8 911, `#?#` extended
CSS 4 788) are recognised and skipped, not misparsed.

---

## 5. Performance, and two bugs worth writing down

The first working version was correct and unusably slow. Both defects were
design errors, not tuning problems, and both are instructive.

### Bug 1 — indexing on the *first* gram

The shortcut table keyed each rule on the **first 4 bytes** of its longest
literal. Tens of thousands of rules start with `http`, `/ads`, `.com`, so one
probe dragged in a bucket of thousands, and each candidate paid a full
`url.find(shortcut)`.

**Fix: index on the *rarest* gram.** Count the global frequency of every 4-gram
across all shortcuts, then file each rule under the least common gram it
contains. Correctness is untouched — if the shortcut occurs in the URL then
*every* gram of it occurs, including the rarest — but buckets collapse.

Two bonuses fall out:
- the gram is 4 bytes, so it packs into a `uint32_t`: integer hashing, no string
  hashing, no allocation per probe;
- we store *where* the gram sits inside the shortcut, so verification is one
  `memcmp` at a known offset instead of a search.

`1204 µs → 137 µs.`

### Bug 2 — `hostSpan` recomputed per candidate

`||` rules need the URL's host span. `matchesPattern` derived it itself, and it
costs three passes over the URL (`find("://")`, a scan for `/?#`, an `rfind('@')`).
`match()` tries thousands of candidates against **one** URL. Hoisting it into
`Request` and passing it down:

`137 µs → 44 µs.`

Found by bisecting with a one-line experiment rather than guessing: stub
`matchesPattern` to `return false` and re-measure. It accounted for 72 % of the
time, which pointed straight at it.

### Where it landed

```
load        : 4 files, 388 262 lines, ~1.7 s
match       : 43.8 µs/request average
              10–25 µs typical
             194 µs worst (google-analytics.com/analytics.js — thousands of
                           rules legitimately contain the literal "analytics")
```

27× faster than the first version. For scale: a 250-request page spends ~11 ms
total in the matcher, against ~1 ms of TLS handshake *per connection*. uBlock
Origin is roughly 10 µs; we are ~4× slower and it is invisible at this scale.
The remaining gap is candidate volume, which would need Aho-Corasick or uBlock's
frequency-ranked token selection to close.

### Bug 3 — 250 KB of CSS on every page

`cssFor(host)` concatenated all **15 821** generic `##` selectors. 250 KB
injected into every response, 5.9 ms to build.

**Fix, and it exploits our position:** a browser extension must inject generic
cosmetic filters before it can see the DOM. *We are a proxy* — we hold the
document. So index generic selectors by their most selective class/id token,
scan the HTML for the class and id values actually present, and emit only the
selectors that can possibly match.

`250 471 B / 5.9 ms → 20 656 B / 0.17 ms.`

The 20 KB floor is 549 selectors that cannot be reduced to a token —
`[id^="ezoic-pub-ad-placeholder-"]`, `[class*="…"]`, `div[data-testid="…"]`.
Those are always emitted, which is the safe direction.

The tradeoff, stated plainly: a generic rule like `ins.adsbygoogle` is dropped
when the served HTML contains no such class, so it will not hide an element that
JavaScript injects later. Domain-specific rules are always emitted, and our
learncpp rules are domain-specific, so the page we care about is unaffected.

---

## 6. What is actually built

```
src/url.cpp        172   URL split, subdomain match, registrable domain
src/parser.cpp     560   rule grammar, shortcut extraction, glob + PCRE2 matcher
src/engine.cpp     490   three-table index, cheapest-first match pipeline
src/cosmetic.cpp   ~330  element hiding, token-reduced generics
src/ca.cpp         510   local CA, on-the-fly leaf certs, TLS contexts
src/http.cpp       473   HTTP/1.1 parse/serialize, chunked, gzip
src/proxy.cpp      942   CONNECT MITM, request loop, CSS injection, tunneling
src/main.cpp       233   CLI
tests/            1 100  100 tests, 0 failures
```

Verified beyond the unit tests:
- real TLS handshake over a BIO pair; browser side trusting only our CA;
  TLSv1.3 negotiated, `SSL_get_verify_result == X509_V_OK`, ALPN `http/1.1`
- upstream certificate verification against the system store is enforced
- `https://self-signed.badssl.com` fails the upstream handshake and falls back
  to a **blind byte tunnel** — the pinned-cert escape hatch from notes/03 §2
- chunked upload and download, keep-alive reuse, HEAD, POST, 3 MB body relayed
  byte-identical
- header surgery: hop-by-hop stripped, `Accept-Encoding` forced to `gzip` for
  documents, `br`/`zstd` removed elsewhere, `DNT`/`Sec-GPC` added,
  `X-Client-Data`/`If-None-Match`/`ETag`/`Alt-Svc` removed

---

## 7. Using it

```bash
cmake -B build && cmake --build build -j8

# 1. create the CA and trust it
./build/adb --print-ca                     # prints the path + PEM

#    Firefox : Settings > Privacy & Security > Certificates > View Certificates
#              > Authorities > Import > tick "Trust this CA to identify websites"
#    Chrome  : chrome://settings/certificates > Authorities > Import
#    system  : sudo cp ~/.config/adb/ca.crt /usr/local/share/ca-certificates/adb.crt
#              && sudo update-ca-certificates

# 2. run it
./build/adb --listen 127.0.0.1:8080 --filters filters

# 3. point the browser at 127.0.0.1:8080 (HTTP and HTTPS)

# check a single URL without starting the proxy:
./build/adb --test https://www.ezojs.com/ezoic/sa.min.js --source learncpp.com --type script
#  -> BLOCK https://www.ezojs.com/ezoic/sa.min.js by ||ezojs.com^
```

**Understand what you are installing.** A CA in your trust store can forge a
certificate for *any* site. Keep `ca.key` at mode 0600 (the code enforces this),
never copy it to another machine, and delete the CA from your trust store when
you stop using this. Our proxy re-verifies every upstream certificate against
the system store precisely because the browser can no longer do it for you — but
you are still moving your trust anchor onto this program.

---

## 8. Honest limitations

- **HTTP/1.1 only.** We advertise only `http/1.1` in ALPN both ways. No
  multiplexing, so page loads are slower than direct. This bought us ~8 000
  lines of nghttp2/ngtcp2 integration we did not write.
- **Manual proxy mode only.** No transparent NAT interception, no root helper,
  no DNS proxy.
- **No scriptlets, no extended CSS, no `$replace`/`$hls`/`$jsonprune`.** These
  are what defeat anti-adblock walls and video pre-rolls. We recognise and skip
  their rules rather than mis-apply them.
- **Generic cosmetic rules are matched against the served HTML**, so they miss
  elements injected later by JavaScript (§5, bug 3).
- **Pinned-certificate sites bypass filtering entirely** by design.
- The matcher is ~4× slower than uBlock Origin. Irrelevant at one user's
  request rate; it would matter as a shared gateway.
