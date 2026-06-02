package assets

// blobput.go — PUT /v1/blob/:sha256 — accept a **direct** client
// upload authorized by a dock-signed PUT grant, so blob bytes never
// traverse the dock (the symmetric of the signed GET in blob.go).
//
// This is the "signed-URL upload" primitive from
// doc/arch/release-system.md §3. The dock mints a scoped grant; the
// client (or the SDK) PUTs the raw bytes straight here.
//
// Flow:
//   1. sha256 from URL path; exp/max/ct/sig from the query.
//   2. verifyDockPutURL → 403 on bad sig / expired / bad params.
//      The grant binds the exact sha key + a max size + an expiry.
//   3. Stream the request body to <BlobDir>/.<rand>.tmp while hashing
//      and counting, refusing to read past `max` (413).
//   4. Recompute sha256 and reject (400) if body_sha != the key — so
//      even a valid grant cannot store mismatched content; the stored
//      key is always the true content hash.
//   5. os.Rename to <BlobDir>/<sha256>; dedup if it already exists.
//
// Unlike /v1/receive (dock→provider, multipart + plugin-HMAC headers),
// this is a raw-body PUT authenticated purely by the URL signature —
// the caller is an untrusted client holding only a scoped grant.

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func (p *Plugin) handleBlobPut(c *gin.Context) {
	sha := strings.TrimSpace(c.Param("sha256"))
	if sha == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sha256 required"})
		return
	}
	// Reject any path-climbing before it can reach the filesystem.
	if strings.ContainsAny(sha, "/\\") || strings.Contains(sha, "..") {
		p.metrics.recordRequest("blob_put", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sha format"})
		return
	}
	maxBytes, err := verifyDockPutURL(
		sha,
		strings.TrimSpace(c.Query("exp")),
		strings.TrimSpace(c.Query("max")),
		c.Query("ct"),
		strings.TrimSpace(c.Query("sig")),
		[]byte(p.DockHMACSecret),
	)
	if err != nil {
		log.Printf("assets: blob put 403 sha=%s reason=%v", sha, err)
		p.metrics.recordRequest("blob_put", "403")
		c.JSON(http.StatusForbidden, gin.H{
			"error":  "invalid upload grant",
			"reason": err.Error(),
		})
		return
	}

	if err := os.MkdirAll(p.BlobDir, 0o700); err != nil {
		p.metrics.recordRequest("blob_put", "500")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "mkdir failed"})
		return
	}
	stagePath := filepath.Join(p.BlobDir, "."+randHex8()+".put.tmp")
	f, err := os.OpenFile(stagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		p.metrics.recordRequest("blob_put", "500")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stage open failed"})
		return
	}

	// Read at most max+1 bytes: if we ever produce that last byte the
	// body exceeded the grant and we reject. Hash + count as we go.
	h := sha256.New()
	limited := io.LimitReader(c.Request.Body, maxBytes+1)
	n, copyErr := io.Copy(io.MultiWriter(f, h), limited)
	_ = f.Close()
	if copyErr != nil {
		_ = os.Remove(stagePath)
		p.metrics.recordRequest("blob_put", "500")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stage write failed"})
		return
	}
	if n > maxBytes {
		_ = os.Remove(stagePath)
		log.Printf("assets: blob put 413 sha=%s exceeded max=%d", sha, maxBytes)
		p.metrics.recordRequest("blob_put", "413")
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body exceeds grant max"})
		return
	}
	computedHex := hex.EncodeToString(h.Sum(nil))
	if computedHex != strings.ToLower(sha) {
		_ = os.Remove(stagePath)
		log.Printf("assets: blob put 400 sha mismatch: key=%s computed=%s", sha, computedHex)
		p.metrics.recordRequest("blob_put", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "sha256 mismatch: body hash != key"})
		return
	}

	finalPath := filepath.Join(p.BlobDir, computedHex)
	if _, statErr := os.Stat(finalPath); statErr == nil {
		// Content-addressed dedup — already have it; drop staging copy.
		_ = os.Remove(stagePath)
		log.Printf("assets: blob put dedup sha=%s size=%d", computedHex, n)
	} else if os.IsNotExist(statErr) {
		if err := os.Rename(stagePath, finalPath); err != nil {
			_ = os.Remove(stagePath)
			p.metrics.recordRequest("blob_put", "500")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "rename failed"})
			return
		}
		log.Printf("assets: blob put stored sha=%s size=%d", computedHex, n)
	} else {
		_ = os.Remove(stagePath)
		p.metrics.recordRequest("blob_put", "500")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stat dst failed"})
		return
	}
	p.metrics.recordRequest("blob_put", "200")
	c.JSON(http.StatusOK, gin.H{
		"sha256":     computedHex,
		"size_bytes": n,
	})
}
