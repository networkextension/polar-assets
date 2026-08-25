package assets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestMimeRE locks the ?ct= validation: real media mimes pass; anything that
// could split the header or smuggle params/junk is rejected (→ octet-stream).
func TestMimeRE(t *testing.T) {
	good := []string{
		"audio/mpeg", "audio/mp4", "audio/flac", "audio/x-m4a", "audio/ogg",
		"video/mp4", "image/jpeg", "image/png", "application/pdf",
	}
	for _, m := range good {
		if !mimeRE.MatchString(m) {
			t.Errorf("expected %q to be accepted", m)
		}
	}
	bad := []string{
		"", "application/octet-stream\r\nSet-Cookie: x=1", "audio/mpeg; charset=x",
		"text/html ", " audio/mpeg", "audio /mpeg", "notamime", "audio/", "/mpeg",
		"audio/mpeg\n", "<script>", "*/*",
	}
	for _, m := range bad {
		if mimeRE.MatchString(m) {
			t.Errorf("expected %q to be rejected", m)
		}
	}
}

// TestDownloadFilename locks the ?name= vetting behind Content-Disposition:
// only the last path element survives, header-splitting/quote characters are
// stripped, junk yields "" (no header at all).
func TestDownloadFilename(t *testing.T) {
	cases := map[string]string{
		"polar-datacollector-v1.0.0-1.apk": "polar-datacollector-v1.0.0-1.apk",
		"polar-ble/S20260901-01/hr.csv":    "hr.csv",
		"  ../../etc/passwd ":              "passwd",
		"a\"b\r\nSet-Cookie: x=1.apk":      "abSet-Cookie: x=1.apk",
		"录音 v2.m4a":                        "录音 v2.m4a",
		"":                                 "",
		"/":                                "",
		"..":                               "",
		"\r\n":                             "",
	}
	for in, want := range cases {
		if got := downloadFilename(in); got != want {
			t.Errorf("downloadFilename(%q) = %q, want %q", in, got, want)
		}
	}
	if got := asciiFallback("录音 v2.m4a"); got != "__ v2.m4a" {
		t.Errorf("asciiFallback = %q", got)
	}
}

// TestHandleBlobGet_ContentDisposition: end-to-end through the handler —
// ?name= becomes Content-Disposition, ?ct= becomes Content-Type, and the
// signed token still verifies with the extra query params present (the
// canonical is sha:exp only, so dock can append them without re-signing).
func TestHandleBlobGet_ContentDisposition(t *testing.T) {
	gin.SetMode(gin.TestMode)
	content := []byte("PK\x03\x04 fake apk")
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])
	plugin, dir := newTestPlugin(t, "shared-secret")
	if err := os.WriteFile(filepath.Join(dir, sha), content, 0o644); err != nil {
		t.Fatal(err)
	}
	exp := strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10)
	mac := hmac.New(sha256.New, []byte("shared-secret"))
	mac.Write([]byte(sha + ":" + exp))
	token := exp + ":" + hex.EncodeToString(mac.Sum(nil))

	get := func(query string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/v1/blob/"+sha+"?token="+token+query, nil)
		c.Params = gin.Params{{Key: "sha256", Value: sha}}
		plugin.handleBlobGet(c)
		return rec
	}

	rec := get("&name=polar-datacollector-v1.0.0-1.apk&ct=application/vnd.android.package-archive")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="polar-datacollector-v1.0.0-1.apk"; filename*=UTF-8''polar-datacollector-v1.0.0-1.apk` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/vnd.android.package-archive" {
		t.Errorf("Content-Type = %q", got)
	}

	// No ?name= → no Content-Disposition (unchanged behaviour for inline media).
	if got := get("").Header().Get("Content-Disposition"); got != "" {
		t.Errorf("unexpected Content-Disposition without name: %q", got)
	}
	// Non-ASCII name → ASCII fallback + RFC 5987 form.
	if got := get("&name=" + url.QueryEscape("录音 v2.m4a")).Header().Get("Content-Disposition"); got != `attachment; filename="__ v2.m4a"; filename*=UTF-8''%E5%BD%95%E9%9F%B3%20v2.m4a` {
		t.Errorf("Content-Disposition (utf8) = %q", got)
	}
}
