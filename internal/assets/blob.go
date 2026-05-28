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
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

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
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid signed url"})
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
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", strconv.FormatInt(stat.Size(), 10))
	c.Header("X-Asset-SHA256", sha)
	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, f); err != nil {
		// Body already started; can't change status. Log so ops sees
		// the rate, but the client already saw partial bytes.
		log.Printf("assets: blob stream interrupted sha=%s: %v", sha, err)
		p.metrics.recordRequest("blob_get", "500")
		return
	}
	p.metrics.recordRequest("blob_get", "200")
}
