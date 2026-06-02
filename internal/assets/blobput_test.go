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

// freshPutGrant mints a signed-PUT grant matching polar-dock's
// buildSignedPutURL: sig = HMAC-SHA256(secret, "PUT\n<sha>\n<exp>\n<max>\n<ct>").
// Returns the four query values the handler reads.
func freshPutGrant(sha string, ttl time.Duration, max int64, ct string, secret []byte) (exp, maxStr, ctOut, sig string) {
	expN := time.Now().Add(ttl).Unix()
	exp = strconv.FormatInt(expN, 10)
	maxStr = strconv.FormatInt(max, 10)
	ctOut = ct
	canonical := "PUT\n" + sha + "\n" + exp + "\n" + maxStr + "\n" + ct
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	sig = hex.EncodeToString(mac.Sum(nil))
	return
}

func shaOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestVerifyDockPutURL_Roundtrip(t *testing.T) {
	secret := []byte("test-secret-bytes-please-rotate-on-deploy")
	body := []byte("hello release world")
	sha := shaOf(body)
	exp, max, ct, sig := freshPutGrant(sha, time.Minute, int64(len(body)), "application/octet-stream", secret)
	got, err := verifyDockPutURL(sha, exp, max, ct, sig, secret)
	if err != nil {
		t.Fatalf("fresh grant failed: %v", err)
	}
	if got != int64(len(body)) {
		t.Errorf("max: got %d want %d", got, len(body))
	}
}

func TestVerifyDockPutURL_RejectsTamperedSha(t *testing.T) {
	secret := []byte("test-secret")
	good := strings.Repeat("ab", 32)
	bad := strings.Repeat("cd", 32)
	exp, max, ct, sig := freshPutGrant(good, time.Minute, 100, "text/plain", secret)
	if _, err := verifyDockPutURL(bad, exp, max, ct, sig, secret); err == nil {
		t.Error("expected mismatch for tampered sha; got nil")
	}
}

func TestVerifyDockPutURL_RejectsTamperedMax(t *testing.T) {
	secret := []byte("test-secret")
	sha := strings.Repeat("a", 64)
	exp, _, ct, sig := freshPutGrant(sha, time.Minute, 100, "", secret)
	// Client tries to widen the grant to 10MB — sig was over max=100.
	if _, err := verifyDockPutURL(sha, exp, "10485760", ct, sig, secret); err == nil {
		t.Error("expected bad sig when max is widened; got nil")
	}
}

func TestVerifyDockPutURL_RejectsExpired(t *testing.T) {
	secret := []byte("test-secret")
	sha := strings.Repeat("a", 64)
	exp, max, ct, sig := freshPutGrant(sha, -time.Hour, 100, "", secret)
	if _, err := verifyDockPutURL(sha, exp, max, ct, sig, secret); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired error, got %v", err)
	}
}

func TestVerifyDockPutURL_RejectsBadSecret(t *testing.T) {
	sha := strings.Repeat("a", 64)
	exp, max, ct, sig := freshPutGrant(sha, time.Minute, 100, "", []byte("good"))
	if _, err := verifyDockPutURL(sha, exp, max, ct, sig, []byte("bad")); err == nil {
		t.Error("expected bad sig with wrong secret; got nil")
	}
}

// A download token (canonical <sha>:<exp>) must NOT validate as a PUT
// grant — verifies the newline/verb-prefixed canonical can't collide.
func TestVerifyDockPutURL_RejectsGetTokenReplay(t *testing.T) {
	secret := []byte("shared-secret")
	sha := strings.Repeat("ab", 32)
	getTok := freshDockToken(sha, time.Minute, secret) // <exp>:<sig> over <sha>:<exp>
	colon := strings.IndexByte(getTok, ':')
	exp := getTok[:colon]
	sig := getTok[colon+1:]
	// Replay the GET sig as a PUT sig with the same exp.
	if _, err := verifyDockPutURL(sha, exp, "100", "application/octet-stream", sig, secret); err == nil {
		t.Error("GET token replayed as PUT grant validated; canonicals collided")
	}
}
