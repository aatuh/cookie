package cookie

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// ErrConsentNotGranted indicates the consent gate prevented setting.
var ErrConsentNotGranted = errors.New("cookie: consent not granted")

// ConsentChecker returns true if a cookie may be set for the request.
type ConsentChecker func(r *http.Request) bool

// EssentialBuilder sets a first-party, secure, HttpOnly cookie with Lax
// SameSite by default. Great for session identifiers and auth tokens.
type EssentialBuilder struct {
	m          *Manager
	name       string
	ttlSeconds int
	hostPrefix bool
}

// NewEssential creates a builder with safe defaults:
//
//	Secure=true, HttpOnly=true, Path="/", SameSite=Lax.
//
// Parameters:
//   - w: The response writer to bind the Manager to.
//   - name: The name of the cookie.
//
// Returns:
//   - *EssentialBuilder: The new builder.
func NewEssential(w http.ResponseWriter, name string) *EssentialBuilder {
	return (&EssentialBuilder{
		m: cookieDefaults(w).
			WithHTTPOnly(true).
			WithSameSite(http.SameSiteLaxMode),
		name:       name,
		ttlSeconds: 0, // session cookie by default
	})
}

// WithTTL sets the cookie TTL. Zero means a session cookie.
//
// Parameters:
//   - ttl: The TTL to set.
//
// Returns:
//   - *EssentialBuilder: The builder with the TTL set.
func (b *EssentialBuilder) WithTTL(ttl time.Duration) *EssentialBuilder {
	b.ttlSeconds = durToSec(ttl)
	return b
}

// WithPath sets the Path attribute (defaults to "/").
//
// Parameters:
//   - path: The path to set.
//
// Returns:
//   - *EssentialBuilder: The builder with the Path set.
func (b *EssentialBuilder) WithPath(path string) *EssentialBuilder {
	b.m = b.m.WithPath(path)
	return b
}

// WithDomain sets the Domain attribute. Not allowed with Host prefix.
//
// Parameters:
//   - domain: The domain to set.
//
// Returns:
//   - *EssentialBuilder: The builder with the Domain set.
func (b *EssentialBuilder) WithDomain(domain string) *EssentialBuilder {
	b.m = b.m.WithDomain(domain)
	return b
}

// WithHostPrefix enforces "__Host-" prefix (Path="/" and no Domain).
//
// Parameters:
//   - enable: The value to set.
//
// Returns:
//   - *EssentialBuilder: The builder with the Host prefix set.
func (b *EssentialBuilder) WithHostPrefix(enable bool) *EssentialBuilder {
	b.hostPrefix = enable
	if enable {
		b.m = b.m.WithPath("/").WithDomain("")
	}
	return b
}

// WithSigner configures HMAC signing for SetSigned().
//
// Parameters:
//   - s: The signer to set.
//
// Returns:
//   - *EssentialBuilder: The builder with the Signer set.
func (b *EssentialBuilder) WithSigner(s Signer) *EssentialBuilder {
	b.m = b.m.WithSigner(s)
	return b
}

// WithEncrypter configures AEAD for SetEncrypted()/SetJSON().
//
// Parameters:
//   - e: The encrypter to set.
//
// Returns:
//   - *EssentialBuilder: The builder with the Encrypter set.
func (b *EssentialBuilder) WithEncrypter(e Encrypter) *EssentialBuilder {
	b.m = b.m.WithEncrypter(e)
	return b
}

// WithSameSite sets SameSite (Lax by default). "None" requires Secure.
//
// Parameters:
//   - s: The SameSite to set.
//
// Returns:
//   - *EssentialBuilder: The builder with the SameSite set.
func (b *EssentialBuilder) WithSameSite(s http.SameSite) *EssentialBuilder {
	b.m = b.m.WithSameSite(s)
	return b
}

// WithPartitioned toggles the Partitioned attribute (Go 1.23+).
//
// Parameters:
//   - v: The value to set.
//
// Returns:
//   - *EssentialBuilder: The builder with the Partitioned set.
func (b *EssentialBuilder) WithPartitioned(v bool) *EssentialBuilder {
	b.m = b.m.WithPartitioned(v)
	return b
}

// Set writes a plain cookie value with the configured defaults.
//
// Parameters:
//   - value: The value to set.
//
// Returns:
//   - error: The error if the cookie cannot be set.
func (b *EssentialBuilder) Set(value string) error {
	name := b.maybeHostPrefix(b.name)
	_, err := b.m.SetCookie(name, value, b.ttlSeconds)
	return err
}

// SetSigned writes a signed (and optionally encrypted) value.
//
// Parameters:
//   - plain: The plaintext value to sign.
//
// Returns:
//   - error: The error if the cookie cannot be set.
func (b *EssentialBuilder) SetSigned(plain string) error {
	name := b.maybeHostPrefix(b.name)
	_, err := b.m.SetSigned(name, plain, b.ttlSeconds)
	return err
}

// SetEncrypted writes an AEAD-encrypted value.
//
// Parameters:
//   - plain: The plaintext value to encrypt.
//
// Returns:
//   - error: The error if the cookie cannot be set.
func (b *EssentialBuilder) SetEncrypted(plain []byte) error {
	name := b.maybeHostPrefix(b.name)
	_, err := b.m.SetEncrypted(name, plain, b.ttlSeconds)
	return err
}

// SetJSON marshals v to JSON (encrypted if encrypter is set) and writes it.
//
// Parameters:
//   - v: The value to set.
//
// Returns:
//   - error: The error if the cookie cannot be set.
func (b *EssentialBuilder) SetJSON(v any) error {
	name := b.maybeHostPrefix(b.name)
	_, err := b.m.SetJSON(name, v, b.ttlSeconds)
	return err
}

// Delete removes the cookie (and signature companion).
//
// Returns:
//   - void: The cookie is deleted.
func (b *EssentialBuilder) Delete() {
	name := b.maybeHostPrefix(b.name)
	b.m.Delete(name)
}

func (b *EssentialBuilder) maybeHostPrefix(n string) string {
	if b.hostPrefix && !strings.HasPrefix(n, "__Host-") {
		return "__Host-" + n
	}
	return n
}

// AnalyticsBuilder sets a client-readable cookie intended for analytics.
// Defaults: Secure=true, HttpOnly=false, SameSite=None (cross-site flows).
// Optionally use Partitioned cookies and a consent checker gate.
type AnalyticsBuilder struct {
	m          *Manager
	name       string
	ttlSeconds int
	consent    ConsentChecker
	hostPrefix bool
}

// NewAnalytics creates a builder with defaults suitable for analytics:
//
//	Secure=true, HttpOnly=false, Path="/", SameSite=None.
//
// Parameters:
//   - w: The response writer to bind the Manager to.
//   - name: The name of the cookie.
//
// Returns:
//   - *AnalyticsBuilder: The new builder.
func NewAnalytics(w http.ResponseWriter, name string) *AnalyticsBuilder {
	return (&AnalyticsBuilder{
		m: cookieDefaults(w).
			WithHTTPOnly(false).
			WithSameSite(http.SameSiteNoneMode),
		name:       name,
		ttlSeconds: durToSec(180 * 24 * time.Hour), // 180 days
	})
}

// WithTTL sets TTL for analytics cookie.
//
// Parameters:
//   - ttl: The TTL to set.
//
// Returns:
//   - *AnalyticsBuilder: The builder with the TTL set.
func (b *AnalyticsBuilder) WithTTL(ttl time.Duration) *AnalyticsBuilder {
	b.ttlSeconds = durToSec(ttl)
	return b
}

// WithDomain sets Domain for wider scoping (e.g., ".example.com").
//
// Parameters:
//   - domain: The domain to set.
//
// Returns:
//   - *AnalyticsBuilder: The builder with the Domain set.
func (b *AnalyticsBuilder) WithDomain(domain string) *AnalyticsBuilder {
	b.m = b.m.WithDomain(domain)
	return b
}

// WithPath sets the Path attribute (defaults to "/").
//
// Parameters:
//   - path: The path to set.
//
// Returns:
//   - *AnalyticsBuilder: The builder with the Path set.
func (b *AnalyticsBuilder) WithPath(path string) *AnalyticsBuilder {
	b.m = b.m.WithPath(path)
	return b
}

// WithPartitioned toggles Partitioned attribute (Go 1.23+).
//
// Parameters:
//   - v: The value to set.
//
// Returns:
//   - *AnalyticsBuilder: The builder with the Partitioned set.
func (b *AnalyticsBuilder) WithPartitioned(v bool) *AnalyticsBuilder {
	b.m = b.m.WithPartitioned(v)
	return b
}

// WithConsentChecker sets an optional gate; if it returns false, Set*
// returns ErrConsentNotGranted and does not write a cookie.
//
// Parameters:
//   - fn: The consent checker to set.
//
// Returns:
//   - *AnalyticsBuilder: The builder with the ConsentChecker set.
func (b *AnalyticsBuilder) WithConsentChecker(
	fn ConsentChecker,
) *AnalyticsBuilder {
	b.consent = fn
	return b
}

// WithHostPrefix enforces "__Host-" prefix (Path="/" and no Domain).
//
// Parameters:
//   - enable: The value to set.
//
// Returns:
//   - *AnalyticsBuilder: The builder with the Host prefix set.
func (b *AnalyticsBuilder) WithHostPrefix(enable bool) *AnalyticsBuilder {
	b.hostPrefix = enable
	if enable {
		b.m = b.m.WithPath("/").WithDomain("")
	}
	return b
}

// Set writes a client-readable value. Honors the consent gate.
//
// Parameters:
//   - r: The request to set the cookie in.
//   - value: The value to set.
//
// Returns:
//   - error: The error if the cookie cannot be set.
func (b *AnalyticsBuilder) Set(r *http.Request, value string) error {
	if b.consent != nil && !b.consent(r) {
		return ErrConsentNotGranted
	}
	name := b.maybeHostPrefix(b.name)
	_, err := b.m.SetCookie(name, value, b.ttlSeconds)
	return err
}

// SetID is a convenience for ID-like values.
//
// Parameters:
//   - r: The request to set the cookie in.
//   - id: The ID to set.
//
// Returns:
//   - error: The error if the cookie cannot be set.
func (b *AnalyticsBuilder) SetID(r *http.Request, id string) error {
	return b.Set(r, id)
}

// Delete removes the analytics cookie.
//
// Returns:
//   - void: The cookie is deleted.
func (b *AnalyticsBuilder) Delete() {
	name := b.maybeHostPrefix(b.name)
	b.m.Delete(name)
}

func (b *AnalyticsBuilder) maybeHostPrefix(n string) string {
	if b.hostPrefix && !strings.HasPrefix(n, "__Host-") {
		return "__Host-" + n
	}
	return n
}

// ThirdPartyBuilder targets cross-site contexts, typically for marketing
// or federated flows. Defaults: Secure=true, HttpOnly=false,
// SameSite=None, Partitioned=false (opt-in via WithPartitioned).
type ThirdPartyBuilder struct {
	m          *Manager
	name       string
	ttlSeconds int
	hostPrefix bool
}

// NewThirdParty creates a builder geared for cross-site usage:
//
//	Secure=true, HttpOnly=false, Path="/", SameSite=None.
//
// Parameters:
//   - w: The response writer to bind the Manager to.
//   - name: The name of the cookie.
//
// Returns:
//   - *ThirdPartyBuilder: The new builder.
func NewThirdParty(w http.ResponseWriter, name string) *ThirdPartyBuilder {
	return (&ThirdPartyBuilder{
		m: cookieDefaults(w).
			WithHTTPOnly(false).
			WithSameSite(http.SameSiteNoneMode),
		name:       name,
		ttlSeconds: durToSec(90 * 24 * time.Hour),
	})
}

// WithTTL sets TTL.
//
// Parameters:
//   - ttl: The TTL to set.
//
// Returns:
//   - *ThirdPartyBuilder: The builder with the TTL set.
func (b *ThirdPartyBuilder) WithTTL(ttl time.Duration) *ThirdPartyBuilder {
	b.ttlSeconds = durToSec(ttl)
	return b
}

// WithDomain sets Domain (e.g., ".example.com").
//
// Parameters:
//   - domain: The domain to set.
//
// Returns:
//   - *ThirdPartyBuilder: The builder with the Domain set.
func (b *ThirdPartyBuilder) WithDomain(domain string) *ThirdPartyBuilder {
	b.m = b.m.WithDomain(domain)
	return b
}

// WithPath sets Path.
//
// Parameters:
//   - path: The path to set.
//
// Returns:
//   - *ThirdPartyBuilder: The builder with the Path set.
func (b *ThirdPartyBuilder) WithPath(path string) *ThirdPartyBuilder {
	b.m = b.m.WithPath(path)
	return b
}

// WithPartitioned toggles Partitioned attribute (Go 1.23+).
//
// Parameters:
//   - v: The value to set.
//
// Returns:
//   - *ThirdPartyBuilder: The builder with the Partitioned set.
func (b *ThirdPartyBuilder) WithPartitioned(v bool) *ThirdPartyBuilder {
	b.m = b.m.WithPartitioned(v)
	return b
}

// WithHostPrefix enforces "__Host-" prefix (Path="/" and no Domain).
//
// Parameters:
//   - enable: The value to set.
//
// Returns:
//   - *ThirdPartyBuilder: The builder with the Host prefix set.
func (b *ThirdPartyBuilder) WithHostPrefix(enable bool) *ThirdPartyBuilder {
	b.hostPrefix = enable
	if enable {
		b.m = b.m.WithPath("/").WithDomain("")
	}
	return b
}

// Set writes the value with the configured attributes.
//
// Parameters:
//   - value: The value to set.
//
// Returns:
//   - error: The error if the cookie cannot be set.
func (b *ThirdPartyBuilder) Set(value string) error {
	name := b.maybeHostPrefix(b.name)
	_, err := b.m.SetCookie(name, value, b.ttlSeconds)
	return err
}

// Delete removes the cookie.
//
// Returns:
//   - void: The cookie is deleted.
func (b *ThirdPartyBuilder) Delete() {
	name := b.maybeHostPrefix(b.name)
	b.m.Delete(name)
}

func (b *ThirdPartyBuilder) maybeHostPrefix(n string) string {
	if b.hostPrefix && !strings.HasPrefix(n, "__Host-") {
		return "__Host-" + n
	}
	return n
}

// cookieDefaults sets the default values for the Manager.
func cookieDefaults(w http.ResponseWriter) *Manager {
	// Secure=true by default to avoid anti-patterns with SameSite=None.
	return NewCookieManager(w).WithPath("/").WithSecure(true)
}

// durToSec converts a duration to seconds.
func durToSec(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	// Clamp to MaxInt to avoid overflow for very large durations.
	const max = int(^uint(0) >> 1)
	secs := int(d / time.Second)
	if secs < 0 || secs > max {
		return max
	}
	return secs
}
