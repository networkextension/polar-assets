package assets

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// buildSignedPullReq forges the exact HMAC headers dock would
// attach when calling POST /v1/pull.
func buildSignedPullReq(t *testing.T, slug string, secret []byte, payload pullReq) *http.Request {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/pull", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	bodySum := sha256.Sum256(body)
	canonical := "POST\n/v1/pull\n" + ts + "\n" + hex.EncodeToString(bodySum[:])
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Polar-Plugin-Name", slug)
	req.Header.Set("X-Polar-Plugin-Timestamp", ts)
	req.Header.Set("X-Polar-Plugin-Sig", sig)
	return req
}

func TestHandlePull_HappyPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	content := []byte("hello from origin provider")
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])

	// Stand up a fake origin provider that serves the blob.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer origin.Close()

	plugin, dir := newTestPlugin(t, "shared-secret")

	req := buildSignedPullReq(t, "zen-prov-1", []byte("shared-secret"), pullReq{
		SHA256:    sha,
		SourceURL: origin.URL + "/v1/blob/" + sha + "?token=irrelevant-for-this-test",
		SizeBytes: int64(len(content)),
	})
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	plugin.handlePull(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(dir, sha))
	if err != nil {
		t.Fatalf("blob missing: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("blob content mismatch")
	}
}

func TestHandlePull_ShaMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	content := []byte("origin returns these bytes")
	bogusSHA := strings.Repeat("ab", 32)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer origin.Close()

	plugin, dir := newTestPlugin(t, "s")

	req := buildSignedPullReq(t, "p", []byte("s"), pullReq{
		SHA256:    bogusSHA,
		SourceURL: origin.URL,
	})
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	plugin.handlePull(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "sha256 mismatch") {
		t.Errorf("expected sha mismatch, got %q", rec.Body.String())
	}
	// No final-named blob should exist (the bogus sha would never
	// land); staging file must also be cleaned up.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected empty blob dir, got %d entries", len(entries))
	}
}

func TestHandlePull_UpstreamError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sha := strings.Repeat("c", 64)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer origin.Close()

	plugin, _ := newTestPlugin(t, "s")

	req := buildSignedPullReq(t, "p", []byte("s"), pullReq{
		SHA256:    sha,
		SourceURL: origin.URL,
	})
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	plugin.handlePull(c)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestHandlePull_DedupFastPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	content := []byte("already cached")
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])

	// origin should NOT be hit; we'll fail the test if it is.
	originHit := false
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHit = true
		_, _ = w.Write(content)
	}))
	defer origin.Close()

	plugin, dir := newTestPlugin(t, "s")
	// Pre-seed the blob.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, sha), content, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := buildSignedPullReq(t, "p", []byte("s"), pullReq{
		SHA256:    sha,
		SourceURL: origin.URL,
	})
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	plugin.handlePull(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"dedup":true`) {
		t.Errorf("expected dedup=true, got %q", rec.Body.String())
	}
	if originHit {
		t.Errorf("origin was called despite local copy")
	}
}

func TestHandlePull_BadSig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	plugin, _ := newTestPlugin(t, "real-secret")

	req := buildSignedPullReq(t, "p", []byte("wrong-secret"), pullReq{
		SHA256:    strings.Repeat("d", 64),
		SourceURL: "http://127.0.0.1:1",
	})
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	plugin.handlePull(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}
