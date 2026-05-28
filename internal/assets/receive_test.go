package assets

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"mime/multipart"
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

// buildSignedMultipart constructs the exact body shape
// uploadAssetToProvider sends, then signs it with the same HMAC
// canonical the provider verifies. Returns request + body bytes.
func buildSignedMultipart(t *testing.T, slug string, secret []byte, sha string, content []byte, sizeOverride int64) *http.Request {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	if err := mw.WriteField("expected_sha256", sha); err != nil {
		t.Fatalf("write sha: %v", err)
	}
	size := int64(len(content))
	if sizeOverride > 0 {
		size = sizeOverride
	}
	if err := mw.WriteField("size_bytes", strconv.FormatInt(size, 10)); err != nil {
		t.Fatalf("write size: %v", err)
	}
	fw, err := mw.CreateFormFile("file", "blob.bin")
	if err != nil {
		t.Fatalf("create file part: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write file: %v", err)
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/receive", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	bodySum := sha256.Sum256(body.Bytes())
	canonical := "POST\n/v1/receive\n" + ts + "\n" + hex.EncodeToString(bodySum[:])
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Polar-Plugin-Name", slug)
	req.Header.Set("X-Polar-Plugin-Timestamp", ts)
	req.Header.Set("X-Polar-Plugin-Sig", sig)
	return req
}

func newTestPlugin(t *testing.T, secret string) (*Plugin, string) {
	t.Helper()
	dir := t.TempDir()
	return &Plugin{
		BlobDir:        dir,
		DockHMACSecret: secret,
		metrics:        newAssetsMetrics(),
	}, dir
}

func TestHandleReceive_HappyPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	plugin, dir := newTestPlugin(t, "good-secret")
	content := []byte("the quick brown fox over the lazy dog")
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])

	req := buildSignedMultipart(t, "zen-prov-1", []byte("good-secret"), sha, content, 0)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	plugin.handleReceive(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	// Verify the blob landed at <dir>/<sha>.
	dst := filepath.Join(dir, sha)
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("blob missing: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("blob content mismatch")
	}
}

func TestHandleReceive_RejectsShaMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	plugin, dir := newTestPlugin(t, "s")
	content := []byte("real bytes")
	bogus := strings.Repeat("ff", 32)

	req := buildSignedMultipart(t, "p", []byte("s"), bogus, content, 0)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	plugin.handleReceive(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "sha256 mismatch") {
		t.Errorf("expected sha mismatch error, got %q", rec.Body.String())
	}
	// Staging file should be cleaned up; only the directory remains.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected empty blob dir after rejection, got %d entries", len(entries))
	}
}

func TestHandleReceive_RejectsBadSig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	plugin, _ := newTestPlugin(t, "the-real-secret")
	content := []byte("payload")
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])

	// Sign with WRONG secret.
	req := buildSignedMultipart(t, "p", []byte("wrong-secret"), sha, content, 0)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	plugin.handleReceive(c)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestHandleReceive_DedupOnExistingBlob(t *testing.T) {
	gin.SetMode(gin.TestMode)
	plugin, dir := newTestPlugin(t, "s")
	content := []byte("dedup me")
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])

	// Pre-populate the destination with an older copy.
	preexisting := []byte("pre-existing data with same name")
	if err := os.WriteFile(filepath.Join(dir, sha), preexisting, 0o600); err != nil {
		t.Fatalf("pre-write: %v", err)
	}

	req := buildSignedMultipart(t, "p", []byte("s"), sha, content, 0)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	plugin.handleReceive(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 on dedup, got %d", rec.Code)
	}
	// Verify the pre-existing file was kept (content-addressed: the
	// trust we have is sha → bytes, so dedup is safe even though the
	// pre-existing bytes are different — sha is the only thing the
	// system cares about. We don't overwrite to avoid disturbing
	// other readers mid-stream.)
	got, _ := os.ReadFile(filepath.Join(dir, sha))
	if !bytes.Equal(got, preexisting) {
		t.Errorf("dedup should have kept pre-existing file")
	}
}
