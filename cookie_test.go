package cookie

import (
    "errors"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func getCookieByName(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
    t.Helper()
    resp := rec.Result()
    for _, c := range resp.Cookies() {
        if c != nil && c.Name == name {
            return c
        }
    }
    return nil
}

func TestHMACSigner_Verify(t *testing.T) {
    s := NewHMACSigner([]byte("k-new"), []byte("k-old"))
    sig := s.Sign("sess", "abc")
    if sig == "" {
        t.Fatalf("empty signature")
    }
    if !s.Verify("sess", "abc", sig) {
        t.Fatalf("verify failed for valid signature")
    }
    if s.Verify("sess", "tampered", sig) {
        t.Fatalf("verify should fail for tampered value")
    }
}

func TestAEADEncrypter_RoundTrip(t *testing.T) {
    key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
    e1, err := NewAEADEncrypter(key, nil)
    if err != nil { t.Fatalf("new encrypter: %v", err) }
    enc, err := e1.Encrypt([]byte("hello"))
    if err != nil { t.Fatalf("encrypt: %v", err) }
    pt, err := e1.Decrypt(enc)
    if err != nil { t.Fatalf("decrypt: %v", err) }
    if string(pt) != "hello" { t.Fatalf("roundtrip mismatch: %q", string(pt)) }

    // Wrong key must fail
    bad, _ := NewAEADEncrypter([]byte("0123456789abcdef0123456789abcdee"), nil)
    if _, err := bad.Decrypt(enc); err == nil {
        t.Fatalf("decrypt with wrong key should fail")
    }
}

func TestManager_SetCookie_Guards(t *testing.T) {
    rec := httptest.NewRecorder()
    m := NewCookieManager(rec)
    m = m.WithSecure(false).WithSameSite(http.SameSiteNoneMode)
    if _, err := m.SetCookie("a", "b", 0); !errors.Is(err, ErrSameSiteNoneNeedsSecure) {
        t.Fatalf("expected ErrSameSiteNoneNeedsSecure, got %v", err)
    }

    // Prefix rules
    m = NewCookieManager(rec).WithSecure(false)
    if _, err := m.SetCookie("__Secure-x", "v", 0); !errors.Is(err, ErrPrefixRules) {
        t.Fatalf("expected ErrPrefixRules for __Secure-")
    }
    m = NewCookieManager(rec).WithSecure(true).WithPath("/foo")
    if _, err := m.SetCookie("__Host-x", "v", 0); !errors.Is(err, ErrPrefixRules) {
        t.Fatalf("expected ErrPrefixRules for __Host- path!=/ ")
    }
    m = NewCookieManager(rec).WithSecure(true).WithPath("/").WithDomain("")
    if _, err := m.SetCookie("__Host-x", "v", 0); err != nil {
        t.Fatalf("unexpected error for valid __Host-: %v", err)
    }
}

func TestManager_SizeLimit(t *testing.T) {
    rec := httptest.NewRecorder()
    m := NewCookieManager(rec)
    name := "n"
    // make len(name)+len(value) exceed maxNamePlusValue
    tooBig := make([]byte, maxNamePlusValue)
    if _, err := m.SetCookie(name, string(tooBig), 0); !errors.Is(err, ErrTooLarge) {
        t.Fatalf("expected ErrTooLarge, got %v", err)
    }
}

func TestSetSigned_ReadSigned(t *testing.T) {
    rec := httptest.NewRecorder()
    m := NewCookieManager(rec).WithSecure(true).WithSigner(NewHMACSigner([]byte("k")))
    if _, err := m.SetSigned("sess", "payload", 60); err != nil { t.Fatalf("SetSigned: %v", err) }

    // Build request with emitted cookies
    req := httptest.NewRequest(http.MethodGet, "/", nil)
    for _, c := range rec.Result().Cookies() {
        req.AddCookie(c)
    }
    v, err := m.ReadSigned(req, "sess")
    if err != nil { t.Fatalf("ReadSigned: %v", err) }
    if v != "payload" { t.Fatalf("got %q", v) }
}

func TestSetSigned_WithEncryption(t *testing.T) {
    rec := httptest.NewRecorder()
    e, _ := NewAEADEncrypter([]byte("0123456789abcdef0123456789abcdef"), nil)
    m := NewCookieManager(rec).WithSecure(true).WithSigner(NewHMACSigner([]byte("k"))).WithEncrypter(e)
    if _, err := m.SetSigned("sess", "secret", 120); err != nil { t.Fatalf("SetSigned: %v", err) }
    req := httptest.NewRequest(http.MethodGet, "/", nil)
    for _, c := range rec.Result().Cookies() { req.AddCookie(c) }
    v, err := m.ReadSigned(req, "sess")
    if err != nil { t.Fatalf("ReadSigned: %v", err) }
    if v != "secret" { t.Fatalf("got %q", v) }
}

func TestSetEncrypted_ReadDecrypted(t *testing.T) {
    rec := httptest.NewRecorder()
    e, _ := NewAEADEncrypter([]byte("0123456789abcdef0123456789abcdef"), nil)
    m := NewCookieManager(rec).WithSecure(true).WithEncrypter(e)
    if _, err := m.SetEncrypted("enc", []byte("xyz"), 10); err != nil { t.Fatalf("SetEncrypted: %v", err) }
    req := httptest.NewRequest(http.MethodGet, "/", nil)
    for _, c := range rec.Result().Cookies() { req.AddCookie(c) }
    out, err := m.ReadDecrypted(req, "enc")
    if err != nil { t.Fatalf("ReadDecrypted: %v", err) }
    if string(out) != "xyz" { t.Fatalf("got %q", string(out)) }
}

func TestJSON_Helpers_PlainAndEncrypted(t *testing.T) {
    type payload struct{ A int; B string }

    // Plain base64 JSON
    rec1 := httptest.NewRecorder()
    m1 := NewCookieManager(rec1)
    if _, err := m1.SetJSON("j", payload{A: 1, B: "x"}, 0); err != nil { t.Fatalf("SetJSON: %v", err) }
    req1 := httptest.NewRequest(http.MethodGet, "/", nil)
    for _, c := range rec1.Result().Cookies() { req1.AddCookie(c) }
    var got1 payload
    if err := m1.GetJSON(req1, "j", &got1); err != nil { t.Fatalf("GetJSON: %v", err) }
    if got1.A != 1 || got1.B != "x" { t.Fatalf("unexpected: %+v", got1) }

    // Encrypted JSON
    rec2 := httptest.NewRecorder()
    e, _ := NewAEADEncrypter([]byte("0123456789abcdef0123456789abcdef"), nil)
    m2 := NewCookieManager(rec2).WithEncrypter(e)
    if _, err := m2.SetJSON("j", payload{A: 7, B: "y"}, 0); err != nil { t.Fatalf("SetJSON enc: %v", err) }
    req2 := httptest.NewRequest(http.MethodGet, "/", nil)
    for _, c := range rec2.Result().Cookies() { req2.AddCookie(c) }
    var got2 payload
    if err := m2.GetJSON(req2, "j", &got2); err != nil { t.Fatalf("GetJSON enc: %v", err) }
    if got2.A != 7 || got2.B != "y" { t.Fatalf("unexpected enc: %+v", got2) }

    // Bad base64 triggers ErrInvalidJSON when not encrypted
    rec3 := httptest.NewRecorder()
    m3 := NewCookieManager(rec3)
    // Manually set a malformed value
    http.SetCookie(rec3, &http.Cookie{Name: "j", Value: "not-base64!!"})
    req3 := httptest.NewRequest(http.MethodGet, "/", nil)
    for _, c := range rec3.Result().Cookies() { req3.AddCookie(c) }
    var x payload
    if err := m3.GetJSON(req3, "j", &x); !errors.Is(err, ErrInvalidJSON) {
        t.Fatalf("expected ErrInvalidJSON, got %v", err)
    }
}

func TestDelete_ClearsMainAndSig(t *testing.T) {
    rec := httptest.NewRecorder()
    m := NewCookieManager(rec).WithSecure(true)
    m.Delete("sess")
    cMain := getCookieByName(t, rec, "sess")
    if cMain == nil || cMain.MaxAge != -1 { t.Fatalf("main cookie not deleted") }
    cSig := getCookieByName(t, rec, "sess.sig")
    if cSig == nil || cSig.MaxAge != -1 || !cSig.HttpOnly {
        t.Fatalf("sig cookie not deleted properly")
    }
}

func TestSameSiteConverters(t *testing.T) {
    if v, ok := StringToSameSite("LAX"); !ok || v != http.SameSiteLaxMode { t.Fatalf("StringToSameSite LAX") }
    if s, ok := SameSiteToString(http.SameSiteStrictMode); !ok || s != "strict" { t.Fatalf("SameSiteToString strict") }
    defer func() { _ = recover() }()
    _ = MustStringToSameSite("unknown") // should panic; defer recovers
}

func TestGetCookieHelpers(t *testing.T) {
    req := httptest.NewRequest(http.MethodGet, "/", nil)
    req.AddCookie(&http.Cookie{Name: "a", Value: "1"})
    if c := GetCookieFromRequest(req, "a"); c == nil || c.Value != "1" { t.Fatalf("GetCookieFromRequest") }
    if v := Get(req, "a"); v != "1" { t.Fatalf("Get failed") }
    if GetCookieFromRequest(nil, "a") != nil { t.Fatalf("nil request should return nil") }
}

func TestBuilders_Essential_Defaults_And_HostPrefix(t *testing.T) {
    rec := httptest.NewRecorder()
    b := NewEssential(rec, "auth").WithHostPrefix(true)
    if err := b.Set("v"); err != nil { t.Fatalf("Set: %v", err) }
    c := getCookieByName(t, rec, "__Host-auth")
    if c == nil { t.Fatalf("cookie not set") }
    if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
        t.Fatalf("unexpected attributes: %+v", c)
    }
}

func TestAnalytics_ConsentAndDefaults(t *testing.T) {
    rec := httptest.NewRecorder()
    b := NewAnalytics(rec, "aid").WithConsentChecker(func(r *http.Request) bool { return false })
    req := httptest.NewRequest(http.MethodGet, "/", nil)
    if err := b.Set(req, "id"); !errors.Is(err, ErrConsentNotGranted) {
        t.Fatalf("expected consent error")
    }
    if len(rec.Result().Cookies()) != 0 { t.Fatalf("cookie should not be written when no consent") }

    // Allow and verify attributes
    rec2 := httptest.NewRecorder()
    b2 := NewAnalytics(rec2, "aid")
    if err := b2.Set(req, "id"); err != nil { t.Fatalf("Set: %v", err) }
    c := getCookieByName(t, rec2, "aid")
    if c == nil { t.Fatalf("missing cookie") }
    if !c.Secure || c.HttpOnly || c.SameSite != http.SameSiteNoneMode { t.Fatalf("unexpected analytics attrs: %+v", c) }
    if c.MaxAge <= 0 { t.Fatalf("expected positive MaxAge for default TTL, got %d", c.MaxAge) }
}

func TestThirdParty_Defaults(t *testing.T) {
    rec := httptest.NewRecorder()
    b := NewThirdParty(rec, "tp").WithHostPrefix(true)
    if err := b.Set("x"); err != nil { t.Fatalf("Set: %v", err) }
    c := getCookieByName(t, rec, "__Host-tp")
    if c == nil { t.Fatalf("missing cookie") }
    if !c.Secure || c.HttpOnly || c.SameSite != http.SameSiteNoneMode { t.Fatalf("unexpected third-party attrs: %+v", c) }
}

func TestDurToSec(t *testing.T) {
    if got := durToSec(-1); got != 0 { t.Fatalf("durToSec(-1)=%d", got) }
    if got := durToSec(1500 * time.Millisecond); got != 1 { t.Fatalf("durToSec(1.5s)=%d", got) }
}
