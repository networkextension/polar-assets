package assets

// receive.go — POST /v1/receive — accept a signed multipart blob
// upload from polar-dock, verify HMAC + sha256, persist under
// BlobDir.
//
// Wire format (matches polar-dock's uploadAssetToProvider):
//
//	multipart fields:
//	  expected_sha256  string  (caller's claim; we compute + verify)
//	  size_bytes       string  (caller's claim; cross-check)
//	  file             file    (the blob bytes)
//
//	headers (HMAC plugin auth, signed by dock):
//	  X-Polar-Plugin-Name       = asset_providers.slug for this provider
//	  X-Polar-Plugin-Timestamp  = unix-seconds, must be within ±5min
//	  X-Polar-Plugin-Sig        = hex HMAC over canonical
//	                              METHOD\nPATH\nTS\nhex(sha256(body))
//
// Flow:
//   1. verifyPluginSig (reads + caches body bytes, returns them).
//   2. Re-parse multipart from the cached body.
//   3. Stream file part to <BlobDir>/<sha>.tmp while hashing.
//   4. Compare computed sha256 ↔ expected_sha256; reject 400 on
//      mismatch (deleting the temp file).
//   5. os.Rename to <BlobDir>/<sha>. If destination already exists
//      we keep the existing copy (content-addressed dedup) and just
//      drop the temp.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// randHex8 returns 8 hex chars for the staging filename. Collision
// is astronomically unlikely; we also use O_EXCL on open.
func randHex8() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *Plugin) handleReceive(c *gin.Context) {
	body, err := verifyPluginSig(c.Request, []byte(p.DockHMACSecret))
	if err != nil {
		log.Printf("assets: receive 401 sig-check: %v", err)
		p.metrics.recordRequest("receive", "401")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid plugin signature"})
		return
	}
	// Re-parse multipart from the verified body. gin's helpers want
	// http.Request.Body; verifyPluginSig already reset Body to a
	// bytes-backed reader.
	contentType := c.GetHeader("Content-Type")
	_, params, err := parseMultipartContentType(contentType)
	if err != nil {
		log.Printf("assets: receive 400 content-type: %v", err)
		p.metrics.recordRequest("receive", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad Content-Type"})
		return
	}
	boundary := params["boundary"]
	if boundary == "" {
		p.metrics.recordRequest("receive", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing multipart boundary"})
		return
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var (
		expectedSHA string
		claimedSize int64
		stagePath   string
		gotBytes    int64
		computedHex string
	)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("assets: receive 400 multipart: %v", err)
			p.metrics.recordRequest("receive", "400")
			c.JSON(http.StatusBadRequest, gin.H{"error": "multipart parse failed"})
			return
		}
		switch part.FormName() {
		case "expected_sha256":
			b, _ := io.ReadAll(part)
			expectedSHA = strings.TrimSpace(string(b))
		case "size_bytes":
			b, _ := io.ReadAll(part)
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
				claimedSize = n
			}
		case "file":
			// Write to staging while hashing.
			if err := os.MkdirAll(p.BlobDir, 0o700); err != nil {
				p.metrics.recordRequest("receive", "500")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "mkdir failed"})
				return
			}
			stagePath = filepath.Join(p.BlobDir, "."+randHex8()+".tmp")
			f, err := os.OpenFile(stagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				p.metrics.recordRequest("receive", "500")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "stage open failed"})
				return
			}
			h := sha256.New()
			n, err := io.Copy(io.MultiWriter(f, h), part)
			_ = f.Close()
			if err != nil {
				_ = os.Remove(stagePath)
				p.metrics.recordRequest("receive", "500")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "stage write failed"})
				return
			}
			gotBytes = n
			computedHex = hex.EncodeToString(h.Sum(nil))
		default:
			// Unknown fields are tolerated — silently drained so we
			// don't leave the multipart parser stuck.
			_, _ = io.Copy(io.Discard, part)
		}
	}
	if expectedSHA == "" {
		_ = os.Remove(stagePath)
		p.metrics.recordRequest("receive", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "expected_sha256 required"})
		return
	}
	if stagePath == "" {
		p.metrics.recordRequest("receive", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "file field required"})
		return
	}
	if computedHex != strings.ToLower(expectedSHA) {
		log.Printf("assets: receive 400 sha mismatch: claimed=%s computed=%s", expectedSHA, computedHex)
		_ = os.Remove(stagePath)
		p.metrics.recordRequest("receive", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "sha256 mismatch"})
		return
	}
	if claimedSize > 0 && claimedSize != gotBytes {
		_ = os.Remove(stagePath)
		p.metrics.recordRequest("receive", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "size mismatch"})
		return
	}
	finalPath := filepath.Join(p.BlobDir, computedHex)
	if _, err := os.Stat(finalPath); err == nil {
		// Dedup — already have this content; drop staging copy and
		// reply success so dock can mark asset_locations(ready).
		_ = os.Remove(stagePath)
		log.Printf("assets: receive dedup sha=%s size=%d", computedHex, gotBytes)
	} else if os.IsNotExist(err) {
		if err := os.Rename(stagePath, finalPath); err != nil {
			_ = os.Remove(stagePath)
			p.metrics.recordRequest("receive", "500")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "rename failed"})
			return
		}
		log.Printf("assets: receive stored sha=%s size=%d", computedHex, gotBytes)
	} else {
		_ = os.Remove(stagePath)
		p.metrics.recordRequest("receive", "500")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stat dst failed"})
		return
	}
	p.metrics.recordRequest("receive", "200")
	c.JSON(http.StatusOK, gin.H{
		"sha256":     computedHex,
		"size_bytes": gotBytes,
	})
}

// parseMultipartContentType wraps mime.ParseMediaType.
func parseMultipartContentType(ct string) (string, map[string]string, error) {
	return mime.ParseMediaType(ct)
}
