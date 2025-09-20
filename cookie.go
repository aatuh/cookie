package cookie

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Conservative guard to avoid exceeding typical browser limits once
// attributes are added. 4096 for name+value is common; we leave headroom.
const maxNamePlusValue = 3800

// ErrSameSiteNoneNeedsSecure is returned when SameSite=None is used
// without Secure=true.
var ErrSameSiteNoneNeedsSecure = errors.New(
	"cookie: SameSite=None requires Secure=true",
)

// ErrTooLarge is returned when name+value exceeds a safe limit.
var ErrTooLarge = errors.New(
	"cookie: name+value too large for common browser limits",
)

// ErrPrefixRules is returned when a cookie name violates prefix rules.
var ErrPrefixRules = errors.New(
	"cookie: name violates __Secure-/__Host- prefix requirements",
)

// ErrInvalidJSON is returned when JSON encoding/decoding fails.
var ErrInvalidJSON = errors.New("cookie: invalid JSON payload")

// Signer provides signing and verification for cookie values.
type Signer interface {
	Sign(name, value string) string
	Verify(name, value, sig string) bool
}

// HMACSigner is an HMAC-SHA256 signer with key rotation.
// Keys[0] is used for signing; all keys are accepted for verification.
type HMACSigner struct {
	keys [][]byte
}

// NewHMACSigner constructs an HMAC signer. The first key is used to
// sign; all keys are valid for verification (rotation).
func NewHMACSigner(keys ...[]byte) *HMACSigner {
	cp := make([][]byte, 0, len(keys))
	for _, k := range keys {
		if len(k) > 0 {
			kc := make([]byte, len(k))
			copy(kc, k)
			cp = append(cp, kc)
		}
	}
	return &HMACSigner{keys: cp}
}

// Sign signs a cookie value with the configured keys.
//
// Parameters:
//   - name: The name of the cookie.
//   - value: The value of the cookie.
//
// Returns:
//   - string: The signed cookie value.
func (s *HMACSigner) Sign(name, value string) string {
	if len(s.keys) == 0 {
		return ""
	}
	m := hmac.New(sha256.New, s.keys[0])
	_, _ = m.Write([]byte(name))
	_, _ = m.Write([]byte{0})
	_, _ = m.Write([]byte(value))
	sum := m.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}

// Verify verifies a signed cookie value with the configured keys.
//
// Parameters:
//   - name: The name of the cookie.
//   - value: The value of the cookie.
//   - sig: The signature of the cookie.
//
// Returns:
//   - bool: True if the signature is valid.
func (s *HMACSigner) Verify(name, value, sig string) bool {
	if sig == "" || len(s.keys) == 0 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	for _, k := range s.keys {
		m := hmac.New(sha256.New, k)
		_, _ = m.Write([]byte(name))
		_, _ = m.Write([]byte{0})
		_, _ = m.Write([]byte(value))
		sum := m.Sum(nil)
		if hmac.Equal(sum, raw) {
			return true
		}
	}
	return false
}

// Encrypter provides authenticated encryption for cookie values.
type Encrypter interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(encoded string) ([]byte, error)
}

// AEADEncrypter implements Encrypter using AES-GCM with a random nonce.
// Key must be 16, 24, or 32 bytes (AES-128/192/256).
type AEADEncrypter struct {
	aead cipher.AEAD
	rnd  io.Reader
}

// NewAEADEncrypter constructs an AES-GCM encrypter. If rnd is nil,
// crypto/rand is used.
func NewAEADEncrypter(key []byte, rnd io.Reader) (*AEADEncrypter, error) {
	if rnd == nil {
		rnd = crand.Reader
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AEADEncrypter{aead: aead, rnd: rnd}, nil
}

// Encrypt encrypts a plaintext value.
//
// Parameters:
//   - plaintext: The plaintext value to encrypt.
//
// Returns:
//   - string: The encrypted value.
func (e *AEADEncrypter) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(e.rnd, nonce); err != nil {
		return "", err
	}
	ct := e.aead.Seal(nil, nonce, plaintext, nil)
	out := append(nonce, ct...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Decrypt decrypts an encoded value.
//
// Parameters:
//   - encoded: The encoded value to decrypt.
//
// Returns:
//   - []byte: The decrypted value.
func (e *AEADEncrypter) Decrypt(encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) < e.aead.NonceSize() {
		return nil, errors.New("cookie: ciphertext too short")
	}
	nonce := raw[:e.aead.NonceSize()]
	ct := raw[e.aead.NonceSize():]
	return e.aead.Open(nil, nonce, ct, nil)
}

// Manager manages cookie creation and reading with sane defaults.
type Manager struct {
	w           http.ResponseWriter
	path        string
	domain      string
	secure      bool
	httpOnly    bool
	sameSite    http.SameSite
	partitioned bool
	signer      Signer
	encrypter   Encrypter
	now         func() time.Time
}

// NewCookieManager creates a Manager bound to w with defaults:
// Path="/", HttpOnly=true, Secure=false, SameSite=Lax.
//
// Parameters:
//   - w: The response writer to bind the Manager to.
//
// Returns:
//   - *Manager: The new Manager.
func NewCookieManager(w http.ResponseWriter) *Manager {
	return &Manager{
		w:        w,
		path:     "/",
		httpOnly: true,
		secure:   false,
		sameSite: http.SameSiteLaxMode,
		now:      time.Now,
	}
}

// WithDomain sets the Domain attribute. For "__Host-" cookies, Domain
// must remain empty.
//
// Parameters:
//   - domain: The domain to set.
//
// Returns:
//   - *Manager: The Manager with the domain set.
func (m *Manager) WithDomain(domain string) *Manager {
	m.domain = domain
	return m
}

// WithPath sets the Path attribute.
//
// Parameters:
//   - path: The path to set.
//
// Returns:
//   - *Manager: The Manager with the path set.
func (m *Manager) WithPath(path string) *Manager {
	if path == "" {
		path = "/"
	}
	m.path = path
	return m
}

// WithHTTPOnly toggles HttpOnly.
//
// Parameters:
//   - v: The value to set.
//
// Returns:
//   - *Manager: The Manager with the HttpOnly set.
func (m *Manager) WithHTTPOnly(v bool) *Manager {
	m.httpOnly = v
	return m
}

// WithSecure toggles Secure.
//
// Parameters:
//   - v: The value to set.
//
// Returns:
//   - *Manager: The Manager with the Secure set.
func (m *Manager) WithSecure(v bool) *Manager {
	m.secure = v
	return m
}

// WithSameSite sets SameSite.
//
// Parameters:
//   - v: The value to set.
//
// Returns:
//   - *Manager: The Manager with the SameSite set.
func (m *Manager) WithSameSite(v http.SameSite) *Manager {
	m.sameSite = v
	return m
}

// WithPartitioned toggles the Partitioned attribute (Go 1.23+).
//
// Parameters:
//   - v: The value to set.
//
// Returns:
//   - *Manager: The Manager with the Partitioned set.
func (m *Manager) WithPartitioned(v bool) *Manager {
	m.partitioned = v
	return m
}

// WithSigner sets the signer used for SetSigned and ReadSigned.
//
// Parameters:
//   - s: The signer to set.
//
// Returns:
//   - *Manager: The Manager with the Signer set.
func (m *Manager) WithSigner(s Signer) *Manager {
	m.signer = s
	return m
}

// WithEncrypter sets the encrypter used by SetEncrypted/ReadDecrypted
// and SetJSON/GetJSON when enabled.
//
// Parameters:
//   - e: The encrypter to set.
//
// Returns:
//   - *Manager: The Manager with the Encrypter set.
func (m *Manager) WithEncrypter(e Encrypter) *Manager {
	m.encrypter = e
	return m
}

// SetCookie writes a cookie with the configured defaults. ttlSeconds
// controls Max-Age; <=0 means a session cookie. Returns the cookie.
//
// Parameters:
//   - name: The name of the cookie.
//   - value: The value of the cookie.
//   - ttlSeconds: The TTL in seconds.
//
// Returns:
//   - *http.Cookie: The set cookie.
func (m *Manager) SetCookie(
	name, value string, ttlSeconds int,
) (*http.Cookie, error) {
	if err := m.guardPrefix(name); err != nil {
		return nil, err
	}
	if err := guardSameSite(m.sameSite, m.secure); err != nil {
		return nil, err
	}
	if len(name)+len(value) > maxNamePlusValue {
		return nil, ErrTooLarge
	}
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     m.path,
		Domain:   m.domain,
		Secure:   m.secure,
		HttpOnly: m.httpOnly,
		SameSite: m.sameSite,
	}
	// Partitioned attribute (Go 1.23+).
	c.Partitioned = m.partitioned

	if ttlSeconds > 0 {
		c.MaxAge = ttlSeconds
		c.Expires = m.now().Add(time.Duration(ttlSeconds) * time.Second)
	}
	// For delete, caller should pass ttlSeconds < 0. We expose Delete().
	http.SetCookie(m.w, c)
	return c, nil
}

// Delete removes a cookie by setting Max-Age=-1 and clearing companions.
//
// Parameters:
//   - name: The name of the cookie.
func (m *Manager) Delete(name string) {
	// Main cookie
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     m.path,
		Domain:   m.domain,
		Secure:   m.secure,
		HttpOnly: m.httpOnly,
		SameSite: m.sameSite,
		// expires in the past
		MaxAge:  -1,
		Expires: time.Unix(1, 0).UTC(),
	}
	c.Partitioned = m.partitioned
	http.SetCookie(m.w, c)

	// Companion signature cookie, if any.
	sig := &http.Cookie{
		Name:     name + ".sig",
		Value:    "",
		Path:     m.path,
		Domain:   m.domain,
		Secure:   m.secure,
		HttpOnly: true,
		SameSite: m.sameSite,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0).UTC(),
	}
	sig.Partitioned = m.partitioned
	http.SetCookie(m.w, sig)
}

// SetSigned sets a cookie and its ".sig" companion using the configured
// signer. ttlSeconds behaves as in SetCookie.
//
// Parameters:
//   - name: The name of the cookie.
//   - plain: The plaintext value to sign.
//   - ttlSeconds: The TTL in seconds.
//
// Returns:
//   - *http.Cookie: The set cookie.
func (m *Manager) SetSigned(
	name, plain string, ttlSeconds int,
) (*http.Cookie, error) {
	if m.signer == nil {
		return nil, errors.New("cookie: signer not configured")
	}
	// Optional encryption before signing (defense in depth).
	val := plain
	if m.encrypter != nil {
		enc, err := m.encrypter.Encrypt([]byte(plain))
		if err != nil {
			return nil, err
		}
		val = enc
	}
	c, err := m.SetCookie(name, val, ttlSeconds)
	if err != nil {
		return nil, err
	}
	sig := &http.Cookie{
		Name:     name + ".sig",
		Value:    m.signer.Sign(name, val),
		Path:     m.path,
		Domain:   m.domain,
		Secure:   m.secure,
		HttpOnly: true,
		SameSite: m.sameSite,
	}
	sig.Partitioned = m.partitioned
	if ttlSeconds > 0 {
		sig.MaxAge = ttlSeconds
		sig.Expires = m.now().Add(time.Duration(ttlSeconds) * time.Second)
	}
	http.SetCookie(m.w, sig)
	return c, nil
}

// ReadSigned reads and verifies a signed cookie from r. On success,
// returns the plaintext value (decrypted if encrypter is set).
//
// Parameters:
//   - r: The request to find the cookie in.
//   - name: The name of the cookie to find.
//
// Returns:
//   - string: The value of the cookie.
func (m *Manager) ReadSigned(
	r *http.Request, name string,
) (string, error) {
	if m.signer == nil {
		return "", errors.New("cookie: signer not configured")
	}
	c := GetCookieFromRequest(r, name)
	if c == nil {
		return "", http.ErrNoCookie
	}
	sig := GetCookieFromRequest(r, name+".sig")
	if sig == nil {
		return "", errors.New("cookie: missing signature")
	}
	if !m.signer.Verify(name, c.Value, sig.Value) {
		return "", errors.New("cookie: bad signature")
	}
	// Optional decrypt.
	if m.encrypter != nil {
		b, err := m.encrypter.Decrypt(c.Value)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return c.Value, nil
}

// SetEncrypted sets an encrypted cookie (no signature cookie). It uses
// AEAD to provide authenticity and confidentiality in a single value.
//
// Parameters:
//   - name: The name of the cookie.
//   - plain: The plaintext value to encrypt.
//   - ttlSeconds: The TTL in seconds.
//
// Returns:
//   - *http.Cookie: The set cookie.
func (m *Manager) SetEncrypted(
	name string, plain []byte, ttlSeconds int,
) (*http.Cookie, error) {
	if m.encrypter == nil {
		return nil, errors.New("cookie: encrypter not configured")
	}
	enc, err := m.encrypter.Encrypt(plain)
	if err != nil {
		return nil, err
	}
	return m.SetCookie(name, enc, ttlSeconds)
}

// ReadDecrypted reads an encrypted cookie and returns the plaintext.
//
// Parameters:
//   - r: The request to find the cookie in.
//   - name: The name of the cookie to find.
//
// Returns:
//   - []byte: The decrypted value.
func (m *Manager) ReadDecrypted(
	r *http.Request, name string,
) ([]byte, error) {
	if m.encrypter == nil {
		return nil, errors.New("cookie: encrypter not configured")
	}
	c := GetCookieFromRequest(r, name)
	if c == nil {
		return nil, http.ErrNoCookie
	}
	return m.encrypter.Decrypt(c.Value)
}

// SetJSON marshals v to JSON (compact), optionally encrypts when an
// encrypter is configured, and sets the cookie.
//
// Parameters:
//   - name: The name of the cookie.
//   - v: The value to set.
//   - ttlSeconds: The TTL in seconds.
//
// Returns:
//   - *http.Cookie: The set cookie.
func (m *Manager) SetJSON(
	name string, v any, ttlSeconds int,
) (*http.Cookie, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	if m.encrypter != nil {
		return m.SetEncrypted(name, b, ttlSeconds)
	}
	// Base64 to ensure a safe cookie value.
	val := base64.RawURLEncoding.EncodeToString(b)
	return m.SetCookie(name, val, ttlSeconds)
}

// GetJSON reads a JSON cookie into out. If encrypter is configured,
// it will decrypt first; otherwise it expects base64-encoded JSON.
//
// Parameters:
//   - r: The request to find the cookie in.
//   - name: The name of the cookie to find.
//   - out: The value to read into.
//
// Returns:
//   - error: The error if the JSON cannot be read.
func (m *Manager) GetJSON(
	r *http.Request, name string, out any,
) error {
	c := GetCookieFromRequest(r, name)
	if c == nil {
		return http.ErrNoCookie
	}
	var raw []byte
	var err error
	if m.encrypter != nil {
		raw, err = m.encrypter.Decrypt(c.Value)
		if err != nil {
			return err
		}
	} else {
		raw, err = base64.RawURLEncoding.DecodeString(c.Value)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
		}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	return nil
}

// AuthCookieManager is a small wrapper that fixes a cookie name.
type AuthCookieManager struct {
	inner *Manager
	name  string
}

// NewAuthCookieManager wraps m with a fixed name.
//
// Parameters:
//   - m: The Manager to wrap.
//   - name: The name of the cookie.
//
// Returns:
//   - *AuthCookieManager: The wrapped Manager.
func NewAuthCookieManager(m *Manager, name string) *AuthCookieManager {
	return &AuthCookieManager{inner: m, name: name}
}

// Set writes the auth cookie with ttl in seconds.
//
// Parameters:
//   - value: The value to set.
//   - ttlSeconds: The TTL in seconds.
//
// Returns:
//   - *http.Cookie: The set cookie.
func (a *AuthCookieManager) Set(value string, ttlSeconds int) (*http.Cookie, error) {
	return a.inner.SetCookie(a.name, value, ttlSeconds)
}

// Delete removes the auth cookie (and its signature if present).
func (a *AuthCookieManager) Delete() { a.inner.Delete(a.name) }

// GetCookieFromRequest finds a cookie by name or returns nil.
//
// Parameters:
//   - r: The request to find the cookie in.
//   - name: The name of the cookie to find.
//
// Returns:
//   - *http.Cookie: The found cookie.
func GetCookieFromRequest(r *http.Request, name string) *http.Cookie {
	if r == nil {
		return nil
	}
	cs := r.Cookies()
	for _, c := range cs {
		if c != nil && c.Name == name {
			return c
		}
	}
	return nil
}

// sameSiteStrings is a map of string to SameSite.
var sameSiteStrings = map[string]http.SameSite{
	"lax":     http.SameSiteLaxMode,
	"strict":  http.SameSiteStrictMode,
	"none":    http.SameSiteNoneMode,
	"default": http.SameSiteDefaultMode, // rarely used; maps to zero.
}

// StringToSameSite parses a case-insensitive string into SameSite.
//
// Parameters:
//   - s: The string to parse.
//
// Returns:
//   - (http.SameSite, bool): The parsed SameSite and a boolean indicating success.
func StringToSameSite(s string) (http.SameSite, bool) {
	v, ok := sameSiteStrings[strings.ToLower(strings.TrimSpace(s))]
	return v, ok
}

// MustStringToSameSite parses s or panics.
//
// Parameters:
//   - s: The string to parse.
//
// Returns:
//   - http.SameSite: The parsed SameSite.
func MustStringToSameSite(s string) http.SameSite {
	if v, ok := StringToSameSite(s); ok {
		return v
	}
	panic("cookie: unknown SameSite value: " + s)
}

// SameSiteToString returns a normalized string for SameSite.
//
// Parameters:
//   - s: The SameSite to convert to a string.
//
// Returns:
//   - (string, bool): The normalized string and a boolean indicating success.
func SameSiteToString(s http.SameSite) (string, bool) {
	switch s {
	case http.SameSiteDefaultMode:
		return "default", true
	case http.SameSiteLaxMode:
		return "lax", true
	case http.SameSiteStrictMode:
		return "strict", true
	case http.SameSiteNoneMode:
		return "none", true
	default:
		return "", false
	}
}

// MustSameSiteToString converts s or panics.
//
// Parameters:
//   - s: The SameSite to convert to a string.
//
// Returns:
//   - string: The normalized string.
func MustSameSiteToString(s http.SameSite) string {
	if v, ok := SameSiteToString(s); ok {
		return v
	}
	panic("cookie: unknown SameSite enum: " + strconv.Itoa(int(s)))
}

// guardSameSite enforces "None requires Secure".
func guardSameSite(s http.SameSite, secure bool) error {
	if s == http.SameSiteNoneMode && !secure {
		return ErrSameSiteNoneNeedsSecure
	}
	return nil
}

// guardPrefix enforces "__Secure-" and "__Host-" rules.
//
// "__Secure-" requires Secure=true.
// "__Host-" requires Secure=true, Path="/", and no Domain attribute.
func (m *Manager) guardPrefix(name string) error {
	if strings.HasPrefix(name, "__Secure-") {
		if !m.secure {
			return ErrPrefixRules
		}
	}
	if strings.HasPrefix(name, "__Host-") {
		if !m.secure || m.domain != "" || m.path != "/" {
			return ErrPrefixRules
		}
	}
	return nil
}

// Get returns a cookie value or "" if missing.
//
// Parameters:
//   - r: The request to find the cookie in.
//   - name: The name of the cookie to find.
//
// Returns:
//   - string: The value of the cookie.
func Get(r *http.Request, name string) string {
	if c := GetCookieFromRequest(r, name); c != nil {
		return c.Value
	}
	return ""
}

// ctxKey is a key for storing the Manager in the context.
type ctxKey struct{}

// WithManager returns a new context with Manager stored.
//
// Parameters:
//   - ctx: The context to store the Manager in.
//   - m: The Manager to store.
//
// Returns:
//   - context.Context: The new context with the Manager stored.
func WithManager(ctx context.Context, m *Manager) context.Context {
	return context.WithValue(ctx, ctxKey{}, m)
}

// FromContext retrieves a Manager from ctx if present.
//
// Parameters:
//   - ctx: The context to retrieve the Manager from.
//
// Returns:
//   - (*Manager, bool): The Manager and a boolean indicating success.
func FromContext(ctx context.Context) (*Manager, bool) {
	m, ok := ctx.Value(ctxKey{}).(*Manager)
	return m, ok
}
