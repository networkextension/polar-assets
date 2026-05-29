package assets

// pull.go — POST /v1/pull. Warm-pull a blob from a peer provider.
//
// Wire format (HMAC plugin auth, same shape as /v1/receive):
//
//	body (JSON):
//	  sha256       string  required; the blob hash we want to cache
//	  source_url   string  required; signed dock URL to GET (typically
//	                       the origin provider's /v1/blob/<sha>?token=…)
//	  size_bytes   int64   optional; caller's claim, cross-checked
//
//	response (200): {"sha256": "…", "size_bytes": …}
//
// Flow:
//   1. verifyPluginSig — same dock→provider HMAC as /v1/receive.
//   2. Decode JSON body.
//   3. GET source_url; treat 2xx as the bytes, anything else as a
//      provider-rejected error (502).
//   4. Stream body into <BlobDir>/.<rand>.tmp while hashing.
//   5. sha-mismatch → 400; rename to <BlobDir>/<sha> on match.
//      If the destination already exists, treat as dedup-success.
//
// Why dock mediates the signed URL instead of the target deriving
// it from the origin's hmac_token: providers don't share secrets
// pairwise. Dock has every provider's hmac_token in
// asset_providers; it mints a URL that ONLY the origin can verify.
// The target just fetches it like any HTTPS source.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type pullReq struct {
	SHA256    string `json:"sha256"`
	SourceURL string `json:"source_url"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
}

// pullHTTPClient — shared client with a generous timeout suitable
// for multi-GB warm pulls. We rely on the streaming hash check, not
// the client, to bound failure.
var pullHTTPClient = &http.Client{
	Timeout: 30 * time.Minute,
}

func (p *Plugin) handlePull(c *gin.Context) {
	body, err := verifyPluginSig(c.Request, []byte(p.DockHMACSecret))
	if err != nil {
		log.Printf("assets: pull 401 sig-check: %v", err)
		p.metrics.recordRequest("pull", "401")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid plugin signature"})
		return
	}
	var req pullReq
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("assets: pull 400 json: %v", err)
		p.metrics.recordRequest("pull", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad json"})
		return
	}
	req.SHA256 = strings.ToLower(strings.TrimSpace(req.SHA256))
	if !looksLikeSHA256Hex(req.SHA256) {
		p.metrics.recordRequest("pull", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "sha256 must be 64 hex chars"})
		return
	}
	if strings.TrimSpace(req.SourceURL) == "" {
		p.metrics.recordRequest("pull", "400")
		c.JSON(http.StatusBadRequest, gin.H{"error": "source_url required"})
		return
	}

	// Fast path: we may already have this blob.
	finalPath := filepath.Join(p.BlobDir, req.SHA256)
	if st, err := os.Stat(finalPath); err == nil && !st.IsDir() {
		p.metrics.recordRequest("pull", "200")
		c.JSON(http.StatusOK, gin.H{
			"sha256":     req.SHA256,
			"size_bytes": st.Size(),
			"dedup":      true,
		})
		return
	}

	if err := os.MkdirAll(p.BlobDir, 0o700); err != nil {
		p.metrics.recordRequest("pull", "500")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "mkdir failed"})
		return
	}

	gotSize, err := fetchAndVerify(req.SourceURL, p.BlobDir, req.SHA256, finalPath)
	if err != nil {
		log.Printf("assets: pull fetch failed sha=%s url-host=%s err=%v", req.SHA256, urlHost(req.SourceURL), err)
		// Classify: sha-mismatch → 400 (caller asked for wrong sha
		// OR source is corrupted); anything else → 502 upstream.
		var sm *shaMismatchErr
		if errors.As(err, &sm) {
			p.metrics.recordRequest("pull", "400")
			c.JSON(http.StatusBadRequest, gin.H{"error": "sha256 mismatch", "computed": sm.computed})
			return
		}
		p.metrics.recordRequest("pull", "502")
		c.JSON(http.StatusBadGateway, gin.H{"error": "fetch from source provider failed"})
		return
	}
	if req.SizeBytes > 0 && req.SizeBytes != gotSize {
		// Bytes were verified by sha already; size mismatch is a
		// soft signal but we trust the hash. Log only.
		log.Printf("assets: pull size hint mismatch sha=%s claimed=%d got=%d", req.SHA256, req.SizeBytes, gotSize)
	}
	log.Printf("assets: pull stored sha=%s size=%d", req.SHA256, gotSize)
	p.metrics.recordRequest("pull", "200")
	c.JSON(http.StatusOK, gin.H{
		"sha256":     req.SHA256,
		"size_bytes": gotSize,
	})
}

// shaMismatchErr lets the handler distinguish a verification failure
// (caller's fault — wrong sha or corrupted source) from a fetch
// failure (peer's fault) so the right HTTP code reaches dock.
type shaMismatchErr struct {
	expected string
	computed string
}

func (e *shaMismatchErr) Error() string {
	return fmt.Sprintf("sha mismatch: expected %s got %s", e.expected, e.computed)
}

// fetchAndVerify GETs sourceURL, streams into a temp file under
// blobDir while hashing, verifies the computed sha matches
// expectedSHA, and only then renames to finalPath. On any failure
// (network, non-2xx, sha mismatch) the staging file is removed so
// we never leave a partial / corrupt blob on disk.
//
// Returns the byte count on success. Sha mismatch surfaces as
// *shaMismatchErr so the caller can return 400 instead of 502.
func fetchAndVerify(sourceURL, blobDir, expectedSHA, finalPath string) (int64, error) {
	resp, err := pullHTTPClient.Get(sourceURL)
	if err != nil {
		return 0, fmt.Errorf("get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := make([]byte, 256)
		n, _ := io.ReadFull(resp.Body, snippet)
		return 0, fmt.Errorf("upstream %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet[:n])))
	}
	stagePath := filepath.Join(blobDir, "."+randHex8()+".pull.tmp")
	f, err := os.OpenFile(stagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("stage: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	_ = f.Close()
	if err != nil {
		_ = os.Remove(stagePath)
		return 0, fmt.Errorf("stage write: %w", err)
	}
	computed := hex.EncodeToString(h.Sum(nil))
	if computed != expectedSHA {
		_ = os.Remove(stagePath)
		return 0, &shaMismatchErr{expected: expectedSHA, computed: computed}
	}
	if st, err := os.Stat(finalPath); err == nil && !st.IsDir() {
		// Dedup race — somebody else stored the same blob while
		// we were fetching. Drop the staged copy.
		_ = os.Remove(stagePath)
		return st.Size(), nil
	}
	if err := os.Rename(stagePath, finalPath); err != nil {
		_ = os.Remove(stagePath)
		return 0, fmt.Errorf("rename: %w", err)
	}
	return n, nil
}

// looksLikeSHA256Hex — 64 lowercase hex chars. Cheap reject for
// junk input before we hit the disk.
func looksLikeSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// urlHost extracts the host:port for logging without pulling in
// net/url just for a debug string.
func urlHost(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}
