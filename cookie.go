package cookie

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	sameSiteNone   = "none"
	sameSiteLax    = "lax"
	sameSiteStrict = "strict"
)

// CookieWriter is an interface to write cookies to an HTTP response.
type CookieWriter interface {
	WriteCookie(cookie *http.Cookie)
}

// DefaultCookieWriter implements CookieWriter using http.SetCookie.
type DefaultCookieWriter struct {
	writer http.ResponseWriter
}

// NewDefaultCookieWriter returns a new DefaultCookieWriter.
func NewDefaultCookieWriter(w http.ResponseWriter) *DefaultCookieWriter {
	return &DefaultCookieWriter{writer: w}
}

// WriteCookie writes the cookie using http.SetCookie.
func (w *DefaultCookieWriter) WriteCookie(cookie *http.Cookie) {
	http.SetCookie(w.writer, cookie)
}

// CookieManager manages cookies using common options.
// By default, it uses:
//   - Path:      "/"
//   - HttpOnly:  true
//   - SameSite:  Lax
//   - Domain:    "" (empty)
//   - Secure:    false
type CookieManager struct {
	writer   CookieWriter
	sameSite http.SameSite
	domain   *string
	secure   bool
	httpOnly bool
	path     string
}

// NewCookieManager creates a new CookieManager using the given
// http.ResponseWriter.
//
// Parameters:
//   - w: The http.ResponseWriter to use for writing cookies.
//
// Returns:
//   - *CookieManager: The new CookieManager.
func NewCookieManager(w http.ResponseWriter) *CookieManager {
	manager := &CookieManager{
		writer:   NewDefaultCookieWriter(w),
		sameSite: http.SameSiteLaxMode,
		domain:   nil,
		secure:   false,
		httpOnly: true,
		path:     "/",
	}
	return manager
}

// WithSameSite sets the SameSite attribute and returns a new CookieManager.
//
// Parameters:
//   - sameSite: The http.SameSite value to use.
//
// Returns:
//   - *CookieManager: The new CookieManager.
func (m *CookieManager) WithSameSite(sameSite http.SameSite) *CookieManager {
	new := *m
	new.sameSite = sameSite
	return &new
}

// WithDomain sets the Domain attribute and returns a new CookieManager.
//
// Parameters:
//   - domain: The domain to use.
//
// Returns:
//   - *CookieManager: The new CookieManager.
func (m *CookieManager) WithDomain(domain *string) *CookieManager {
	new := *m
	new.domain = domain
	return &new
}

// WithSecure sets the Secure flag and returns a new CookieManager.
//
// Parameters:
//   - secure: The secure flag to use.
//
// Returns:
//   - *CookieManager: The new CookieManager.
func (m *CookieManager) WithSecure(secure bool) *CookieManager {
	new := *m
	new.secure = secure
	return &new
}

// WithHTTPOnly sets the HttpOnly flag and returns a new CookieManager.
//
// Parameters:
//   - httpOnly: The httpOnly flag to use.
//
// Returns:
//   - *CookieManager: The new CookieManager.
func (m *CookieManager) WithHTTPOnly(httpOnly bool) *CookieManager {
	new := *m
	new.httpOnly = httpOnly
	return &new
}

// WithPath sets the Path attribute and returns a new CookieManager.
//
// Parameters:
//   - path: The path to use.
//
// Returns:
//   - *CookieManager: The new CookieManager.
func (m *CookieManager) WithPath(path string) *CookieManager {
	new := *m
	new.path = path
	return &new
}

// SetCookie sets a cookie with the given name, value, and maxAge (in seconds).
//   - If maxAge < 0, the cookie is deleted.
//   - If maxAge == 0, the cookie is a session cookie (no explicit expiry).
//
// Returns an error if the configuration is inconsistent (for example,
// if SameSite is None but Secure is false).
//
// Parameters:
//   - name: The name of the cookie.
//   - value: The value of the cookie.
//   - maxAge: The maxAge of the cookie.
//
// Returns:
//   - *http.Cookie: The cookie.
//   - error: The error if any.
func (m *CookieManager) SetCookie(
	name, value string,
	maxAge int,
) (*http.Cookie, error) {
	// Validate: SameSite=None must be Secure.
	if m.sameSite == http.SameSiteNoneMode && !m.secure {
		return nil, fmt.Errorf("SameSite=None cookies must be secure")
	}

	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     m.path,
		Secure:   m.secure,
		HttpOnly: m.httpOnly,
		SameSite: m.sameSite,
	}
	if m.domain != nil {
		cookie.Domain = *m.domain
	}
	if maxAge < 0 {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(0, 0)
	} else if maxAge > 0 {
		cookie.MaxAge = maxAge
		cookie.Expires = time.Now().UTC().
			Add(time.Duration(maxAge) * time.Second)
	}
	// For maxAge == 0, no explicit expiration is set.
	m.writer.WriteCookie(cookie)
	return cookie, nil
}

// AuthCookieManager wraps a CookieManager to manage a cookie
// with a fixed name (typically used for authentication).
type AuthCookieManager struct {
	manager    *CookieManager
	cookieName string
}

// NewAuthCookieManager creates an AuthCookieManager for a given cookie name.
//
// Parameters:
//   - manager: The CookieManager to use.
//   - cookieName: The name of the cookie.
//
// Returns:
//   - *AuthCookieManager: The new AuthCookieManager.
func NewAuthCookieManager(
	manager *CookieManager,
	cookieName string,
) *AuthCookieManager {
	return &AuthCookieManager{
		manager:    manager,
		cookieName: cookieName,
	}
}

// Set sets the authentication cookie with the given value and maxAge.
//
// Parameters:
//   - value: The value of the cookie.
//   - maxAge: The maxAge of the cookie.
//
// Returns:
//   - *http.Cookie: The cookie.
//   - error: The error if any.
func (a *AuthCookieManager) Set(
	value string, maxAge int,
) (*http.Cookie, error) {
	return a.manager.SetCookie(a.cookieName, value, maxAge)
}

// GetCookieFromRequest returns the cookie with the specified name from the
// http.Request. If the cookie is not found, it returns nil.
//
// Parameters:
//   - r: The http.Request to use.
//   - name: The name of the cookie.
//
// Returns:
//   - *http.Cookie: The cookie.
func GetCookieFromRequest(
	r *http.Request, name string,
) *http.Cookie {
	c, err := r.Cookie(name)
	if err != nil {
		return nil
	}
	return c
}

// StringToSameSite converts a string to http.SameSite. It returns an error
// if the provided string is invalid.
//
// Parameters:
//   - s: The string to convert.
//
// Returns:
//   - http.SameSite: The http.SameSite value.
//   - error: The error if any.
func StringToSameSite(s string) (http.SameSite, error) {
	switch strings.ToLower(s) {
	case sameSiteNone:
		return http.SameSiteNoneMode, nil
	case sameSiteLax:
		return http.SameSiteLaxMode, nil
	case sameSiteStrict:
		return http.SameSiteStrictMode, nil
	default:
		return 0, fmt.Errorf("invalid SameSite value: %q", s)
	}
}

// MustStringToSameSite converts a string to http.SameSite and panics
// if the string is invalid.
//
// Parameters:
//   - s: The string to convert.
//
// Returns:
//   - http.SameSite: The http.SameSite value.
func MustStringToSameSite(s string) http.SameSite {
	ss, err := StringToSameSite(s)
	if err != nil {
		panic(err)
	}
	return ss
}

// SameSiteToString converts an http.SameSite value to its string
// representation. Returns an error if the value is not recognized.
//
// Parameters:
//   - s: The http.SameSite value.
//
// Returns:
//   - string: The string representation of the http.SameSite value.
//   - error: The error if any.
func SameSiteToString(s http.SameSite) (string, error) {
	switch s {
	case http.SameSiteNoneMode:
		return sameSiteNone, nil
	case http.SameSiteLaxMode:
		return sameSiteLax, nil
	case http.SameSiteStrictMode:
		return sameSiteStrict, nil
	default:
		return "", fmt.Errorf("invalid SameSite value: %v", s)
	}
}

// MustSameSiteToString converts an http.SameSite value to its string
// representation and panics if the value is invalid.
//
// Parameters:
//   - s: The http.SameSite value.
//
// Returns:
//   - string: The string representation of the http.SameSite value.
func MustSameSiteToString(s http.SameSite) string {
	str, err := SameSiteToString(s)
	if err != nil {
		panic(err)
	}
	return str
}
