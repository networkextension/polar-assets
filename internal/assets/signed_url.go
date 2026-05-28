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
