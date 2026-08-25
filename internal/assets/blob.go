package assets

// blob.go — GET /v1/blob/:sha256 — serve a cached blob to the
// caller after verifying the dock-signed URL token.
//
// Flow:
//   1. Pull sha256 from URL path; pull `token` from ?token=…
//   2. verifyDockURL → 403 on bad sig / expired (generic message;
//      reason stays in our log only).
//   3. <BlobDir>/<sha256> open; 404 on miss.
//   4. Stream with Content-Length + Content-Type + X-Asset-SHA256.
//
// 404-on-miss is intentional — P4 warm-pull from peer providers
// kicks in there. For P3 we just say "not here" and let dock route
// somewhere else (or surface a useful error to the user).

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// mimeRE matches a plain "type/subtype" with no parameters/whitespace — used
// to vet the caller-supplied ?ct= before reflecting it into Content-Type, so
// it can't carry header-splitting junk or response params.
var mimeRE = regexp.MustCompile(`^[A-Za-z0-9][\w.+-]*/[A-Za-z0-9][\w.+-]*$`)

// downloadFilename vets the caller-supplied ?name= before it goes into
// Content-Disposition. The blob store is keyed by sha256, so without this the
// browser names the download after the hash (no ".apk"/".csv"). Only the last
// path element is kept; quotes, control chars and anything non-printable are
// dropped; empty/oversized results mean "no header".
func downloadFilename(raw string) string {
	name := filepath.Base(strings.TrimSpace(raw))
	if name == "." || name == "/" || name == ".." {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r == '/':
			continue
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || len(out) > 255 {
		return ""
	}
	return out
}

func (p *Plugin) handleBlobGet(c *gin.Context) {
	sha := strings.TrimSpace(c.Param("sha256"))
	if sha == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sha256 required"})
		return
	}
	token := strings.TrimSpace(c.Query("token"))
	if err := verifyDockURL(token, sha, []byte(p.DockHMACSecret)); err != nil {
		log.Printf("assets: blob 403 sha=%s reason=%v", sha, err)
		p.metrics.recordRequest("blob_get", "403")
		// Surface the failure category (not the secret/sig itself) so
		// an operator hitting the URL directly can diagnose without
		// needing server-log access. Categories include "bad sig",
		// "expired", "malformed token", "missing token or sha",
		// "missing secret", "bad sig hex", "bad exp …".
		c.JSON(http.StatusForbidden, gin.H{
			"error":  "invalid signed url",
			"reason": err.Error(),
		})
		return
	}
	// Reject anything with a path separator so a clever client can't
	// climb out of BlobDir with .. or /.
	if strings.ContainsAny(sha, "/\\") || strings.Contains(sha, "..") {
		p.metrics.recordRequest("blob_get", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sha format"})
		return
	}
	path := filepath.Join(p.BlobDir, sha)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			p.metrics.recordRequest("blob_get", "404")
			c.JSON(http.StatusNotFound, gin.H{"error": "blob not in cache"})
			return
		}
		p.metrics.recordRequest("blob_get", "500")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "open failed"})
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		p.metrics.recordRequest("blob_get", "500")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stat failed"})
		return
	}
	// Serve via http.ServeContent so HTTP Range works: byte-range requests
	// get 206 Partial Content + Accept-Ranges + Content-Range (needed for
	// <audio>/<video> seek and resumable large-file downloads); a plain
	// request still gets a full 200. f is an *os.File (io.ReadSeeker), and
	// ServeContent sets Content-Length itself. We pre-set Content-Type so
	// ServeContent doesn't content-sniff. The blob store is keyed by sha256
	// (no mime of its own), so the caller passes the asset's real mime via
	// ?ct= (dock's download-url / the music svc append it). This matters for
	// Safari: its <audio>/<video> refuse to play application/octet-stream,
	// while Chrome content-sniffs and plays anyway. Vet the value first;
	// fall back to octet-stream on anything unexpected.
	ct := strings.TrimSpace(c.Query("ct"))
	if !mimeRE.MatchString(ct) {
		ct = "application/octet-stream"
	}
	c.Header("Content-Type", ct)
	// ?name= (dock appends the catalog name) → real filename on download.
	// RFC 6266/5987: ASCII fallback in filename=, UTF-8 in filename*=.
	if name := downloadFilename(c.Query("name")); name != "" {
		c.Header("Content-Disposition",
			`attachment; filename="`+asciiFallback(name)+`"; filename*=UTF-8''`+url.PathEscape(name))
	}
	c.Header("X-Asset-SHA256", sha)
	http.ServeContent(c.Writer, c.Request, sha, stat.ModTime(), f)
	p.metrics.recordRequest("blob_get", "200")
}

// asciiFallback replaces non-ASCII runes with '_' for the plain filename=
// parameter; UA's that understand filename*= ignore it anyway.
func asciiFallback(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r > 0x7e {
			b.WriteByte('_')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
