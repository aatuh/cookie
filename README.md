# cookie

Safe, ergonomic helpers for creating, writing, and reading HTTP cookies in Go.

## Install

```bash
go get github.com/aatuh/cookie
```

## Features

* CookieManager with fluent defaults (domain, path, secure, SameSite).
* Signed cookies (HMAC‑SHA256) with key rotation.
* Encrypted cookies (AES‑GCM) with random nonce.
* JSON helpers: `SetJSON` / `GetJSON`.
* Prefix enforcement for `__Secure-` and `__Host-`.
* SameSite guards ("None" requires `Secure=true`).
* `Partitioned` attribute support.
* Robust `Delete` clears both cookie and companion `.sig`.
* Size guard to avoid exceeding typical browser limits.

## Quick start

```go
m := cookie.NewCookieManager(w).
  WithDomain("example.com").
  WithPath("/").
  WithSecure(true).
  WithHTTPOnly(true).
  WithSameSite(http.SameSiteLaxMode)

_, _ = m.SetCookie("session", "abc123", 3600)
// later
val := cookie.Get(r, "session")
_ = val
```

### Signed cookies (with rotation)

```go
sign := cookie.NewHMACSigner([]byte("k1"), []byte("old-k0"))
m := cookie.NewCookieManager(w).WithSecure(true).WithSigner(sign)

_, _ = m.SetSigned("session", "opaque-token", 3600)

v, err := m.ReadSigned(r, "session")
if err != nil { /* handle */ }
fmt.Println(v) // "opaque-token"
```

### Encrypted cookies

```go
aead, _ := cookie.NewAEADEncrypter([]byte("32-byte-secret-key-................"), nil)
m := cookie.NewCookieManager(w).WithSecure(true).WithEncrypter(aead)

// store bytes securely
_, _ = m.SetEncrypted("prefs", []byte("dark:on"), 30*24*3600)

b, _ := m.ReadDecrypted(r, "prefs")
fmt.Println(string(b))
```

### JSON helpers

```go
type Prefs struct{ Theme string `json:"theme"` }
aead, _ := cookie.NewAEADEncrypter([]byte("32-byte-secret-key-................"), nil)
m := cookie.NewCookieManager(w).WithSecure(true).WithEncrypter(aead)

_, _ = m.SetJSON("prefs", Prefs{Theme: "dark"}, 90*24*3600)
var p Prefs
_ = m.GetJSON(r, "prefs", &p)
```

## Prefix rules and SameSite

* `__Secure-<name>` requires `Secure=true`.
* `__Host-<name>` requires `Secure=true`, `Path=/`, and no `Domain`.
* `SameSite=None` requires `Secure=true`.

Violations return descriptive errors.

## Partitioned cookies

```go
m := cookie.NewCookieManager(w).WithSecure(true).WithPartitioned(true)
_, _ = m.SetCookie("__Host-part", "v", 300)
```

`Partitioned` helps limit cross‑site tracking of third‑party cookies. This
field exists in `net/http`.

## Deleting

```go
m.Delete("session") // sets Max-Age=-1 and clears "session.sig" if present
```

## Key rotation (signed cookies)

Create `HMACSigner` with multiple keys. The first key signs new cookies; all
keys verify old ones.

```go
sign := cookie.NewHMACSigner([]byte("new"), []byte("old1"), []byte("old0"))
```

## API surface (selected)

```go
// Construction
NewCookieManager(w http.ResponseWriter) *Manager

// Defaults
(*Manager).WithDomain(string) *Manager
(*Manager).WithPath(string) *Manager
(*Manager).WithHTTPOnly(bool) *Manager
(*Manager).WithSecure(bool) *Manager
(*Manager).WithSameSite(http.SameSite) *Manager
(*Manager).WithPartitioned(bool) *Manager
(*Manager).WithSigner(Signer) *Manager
(*Manager).WithEncrypter(Encrypter) *Manager

// Operations
(*Manager).SetCookie(name, value string, ttlSeconds int) (*http.Cookie, error)
(*Manager).Delete(name string)

// Signed
(*Manager).SetSigned(name, plain string, ttlSeconds int) (*http.Cookie, error)
(*Manager).ReadSigned(r *http.Request, name string) (string, error)

// Encrypted
(*Manager).SetEncrypted(name string, plain []byte, ttlSeconds int) (*http.Cookie, error)
(*Manager).ReadDecrypted(r *http.Request, name string) ([]byte, error)

// JSON
(*Manager).SetJSON(name string, v any, ttlSeconds int) (*http.Cookie, error)
(*Manager).GetJSON(r *http.Request, name string, out any) error

// Utilities
GetCookieFromRequest(r *http.Request, name string) *http.Cookie
Get(r *http.Request, name string) string
```

## Presets

The package includes opinionated builders for common cookie types. These thin
wrappers sit on top of Manager and preconfigure secure, standards-compliant
flags for typical scenarios: essential session cookies, analytics cookies, and
third-party/marketing cookies.

All builders are stdlib-only, composable, and safe to use across handlers.
Prefer these when you want consistent, low-boilerplate cookie handling without
footguns.

### Essential cookies (sessions, auth)

```go
b := NewEssential(w, "session").WithTTL(24*time.Hour)
_ = b.Set("opaque-session-id")
```

### Analytics cookies (with consent gating)

```go
a := NewAnalytics(w, "ga_cid").WithConsentChecker(func(r *http.Request) bool {
  return cookie.Get(r, "consent.analytics") == "true"
})
_ = a.SetID(r, "cid-123") // will no-op with ErrConsentNotGranted if gated
```

### Third-party cookies (marketing, ads)

```go
t := NewThirdParty(w, "__Secure-ad_id").
     WithDomain(".example.com").WithPartitioned(true)
_ = t.Set("some-value")
```

## Notes & limits

* Keep payloads small; browsers commonly limit name+value to \~4096 bytes.
* For large state, prefer server‑side sessions and store a short
  opaque identifier in the cookie.
* Use `Secure=true` in production and `SameSite=Lax` or `Strict` unless a
  cross‑site flow requires `None`.
