# cookie

Helpers for creating, writing, and reading HTTP cookies with sane
defaults and safe SameSite handling.

## Install

```go
import "github.com/aatuh/cookie"
```

## Quick start

```go
// In an HTTP handler
mgr := cookie.NewCookieManager(w).
  WithSameSite(http.SameSiteLaxMode).
  WithHTTPOnly(true).
  WithSecure(true) // set true when using HTTPS

// Set a session cookie (no explicit expiry)
_, _ = mgr.SetCookie("session", "token", 0)

// Delete a cookie
_, _ = mgr.SetCookie("session", "", -1)

// Fixed-name helper
auth := cookie.NewAuthCookieManager(mgr, "auth")
_, _ = auth.Set("jwt", 3600) // expires in seconds

// Read from request
c := cookie.GetCookieFromRequest(r, "auth")
```

## SameSite helpers

```go
ss := cookie.MustStringToSameSite("lax")
name := cookie.MustSameSiteToString(http.SameSiteStrictMode)
_ = ss; _ = name
```

## Notes

- SameSite=None requires `Secure=true`; otherwise `SetCookie` returns an error.
- Defaults: `Path=/`, `HttpOnly=true`, `SameSite=Lax`, `Secure=false`,
  `Domain=""`.
- `AuthCookieManager` is a thin convenience wrapper around `CookieManager`.
