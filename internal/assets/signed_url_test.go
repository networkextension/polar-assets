package assets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

// freshDockToken mints a token matching polar-dock's
// asset_signed_url.go format. Kept here as the test fixture so the
// real dock-side helper doesn't have to be imported.
func freshDockToken(sha string, ttl time.Duration, secret []byte) string {
	exp := time.Now().Add(ttl).Unix()
	canonical := sha + ":" + strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	return strconv.FormatInt(exp, 10) + ":" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyDockURL_Roundtrip(t *testing.T) {
	secret := []byte("test-secret-bytes-please-rotate-on-deploy")
	sha := strings.Repeat("ab", 32)
	tok := freshDockToken(sha, time.Minute, secret)
	if err := verifyDockURL(tok, sha, secret); err != nil {
		t.Errorf("fresh token failed: %v", err)
	}
}

func TestVerifyDockURL_RejectsTamperedSha(t *testing.T) {
	secret := []byte("test-secret")
	good := strings.Repeat("ab", 32)
	bad := strings.Repeat("cd", 32)
	tok := freshDockToken(good, time.Minute, secret)
	if err := verifyDockURL(tok, bad, secret); err == nil {
		t.Error("expected mismatch for tampered sha; got nil")
	}
}

func TestVerifyDockURL_RejectsExpired(t *testing.T) {
	secret := []byte("test-secret")
	sha := strings.Repeat("a", 64)
	tok := freshDockToken(sha, -time.Hour, secret)
	err := verifyDockURL(tok, sha, secret)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired error, got %v", err)
	}
}

func TestVerifyDockURL_RejectsBadSecret(t *testing.T) {
	good := []byte("good")
	bad := []byte("bad")
	sha := strings.Repeat("a", 64)
	tok := freshDockToken(sha, time.Minute, good)
	if err := verifyDockURL(tok, sha, bad); err == nil {
		t.Error("expected bad sig with wrong secret; got nil")
	}
}

func TestVerifyDockURL_RejectsMalformed(t *testing.T) {
	secret := []byte("s")
	sha := strings.Repeat("a", 64)
	for _, tok := range []string{
		"", "no-colon", ":", "123:", ":abc",
		"non_number:abc", "123:not_hex_zz",
	} {
		if err := verifyDockURL(tok, sha, secret); err == nil {
			t.Errorf("token %q should have failed", tok)
		}
	}
}
