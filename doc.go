// Package cookie provides safe, ergonomic helpers for creating, writing,
// and reading HTTP cookies in Go. It includes:
//
//   - CookieManager with fluent defaults (domain/path/secure/samesite).
//   - Signed cookies (HMAC-SHA256) with key rotation.
//   - Encrypted cookies (AES-GCM) with random nonce.
//   - JSON helpers (SetJSON/GetJSON).
//   - Prefix enforcement for "__Secure-" and "__Host-".
//   - SameSite converters and guards for "None requires Secure".
//   - Partitioned attribute support.
//   - Robust delete that also clears any ".sig" companion.
//
// Notes:
//   - If SameSite=None is used, Secure must be true.
//   - Many browsers limit cookie name+value to ~4096 bytes.
//   - For big payloads prefer server-side sessions; encryption here is
//     intended for small, tamper-proof state.
package cookie
