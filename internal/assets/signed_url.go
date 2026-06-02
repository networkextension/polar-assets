package assets

// signed_url.go — verifyDockURL mirrors polar-dock's signAssetURL /
// verifyAssetURL. Dock mints tokens of shape <exp_unix>:<hex_hmac>
// over canonical <sha>:<exp> with HMAC-SHA256(secret, canonical).
// We re-derive the same canonical from URL path (sha256) + the
// token's exp half, recompute HMAC with our DockHMACSecret, and
// constant-time compare.
//
// Keep this file's algorithm in lockstep with polar-dock's
// asset_signed_url.go — any change here must land there too.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// verifyDockURL returns nil if token is well-formed, not expired,
// and the HMAC matches. On any failure returns an error describing
// the category — the caller should NOT echo that string to the
// client (a generic 403 is the right HTTP response).
func verifyDockURL(token, sha256Hex string, secret []byte) error {
	if token == "" || sha256Hex == "" {
		return errors.New("missing token or sha")
	}
	if len(secret) == 0 {
		return errors.New("missing secret")
	}
	colon := strings.IndexByte(token, ':')
	if colon <= 0 || colon == len(token)-1 {
		return errors.New("malformed token")
	}
	expStr := token[:colon]
	sigHex := token[colon+1:]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return fmt.Errorf("bad exp: %w", err)
	}
	if time.Now().Unix() > exp {
		return errors.New("expired")
	}
	canonical := sha256Hex + ":" + expStr
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	wantSigBytes := mac.Sum(nil)
	gotSigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("bad sig hex: %w", err)
	}
	if !hmac.Equal(wantSigBytes, gotSigBytes) {
		return errors.New("bad sig")
	}
	return nil
}

// verifyDockPutURL verifies a dock-signed **upload** grant for
// PUT /v1/blob/<sha256>?exp=<unix>&max=<bytes>&ct=<mime>&sig=<hex>.
//
// It mirrors polar-dock's buildSignedPutURL. The canonical string is
// deliberately newline-delimited and verb-prefixed:
//
//	PUT\n<sha256>\n<exp>\n<max>\n<ct>
//
// so it can NEVER collide with the download token's canonical
// (<sha>:<exp>) — a leaked GET token cannot be replayed as a PUT
// grant, and vice-versa. The grant is object-scoped: sig binds the
// exact sha key, so a token can only write that one blob; max caps
// the body size; exp bounds the window.
//
// Returns the parsed max (bytes) so the handler can enforce it while
// streaming. On any failure returns a category error — same contract
// as verifyDockURL: do NOT echo it as the only client signal, but it
// is safe to surface as a diagnostic `reason` alongside a 403.
func verifyDockPutURL(sha256Hex, expStr, maxStr, ct, sigHex string, secret []byte) (int64, error) {
	if sha256Hex == "" || sigHex == "" {
		return 0, errors.New("missing sha or sig")
	}
	if len(secret) == 0 {
		return 0, errors.New("missing secret")
	}
	if expStr == "" || maxStr == "" {
		return 0, errors.New("missing exp or max")
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad exp: %w", err)
	}
	if time.Now().Unix() > exp {
		return 0, errors.New("expired")
	}
	maxBytes, err := strconv.ParseInt(maxStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad max: %w", err)
	}
	if maxBytes <= 0 {
		return 0, errors.New("non-positive max")
	}
	canonical := "PUT\n" + sha256Hex + "\n" + expStr + "\n" + maxStr + "\n" + ct
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	wantSigBytes := mac.Sum(nil)
	gotSigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return 0, fmt.Errorf("bad sig hex: %w", err)
	}
	if !hmac.Equal(wantSigBytes, gotSigBytes) {
		return 0, errors.New("bad sig")
	}
	return maxBytes, nil
}
