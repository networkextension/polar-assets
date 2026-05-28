package assets

// handlers.go — Phase 2 skeleton handlers for /v1/{blob,receive,pull}.
// Each route returns HTTP 501 with a structured error pointing at the
// phase that ships the real implementation. Once a handler grows real
// logic, move it out into its own file (blob.go / receive.go / pull.go)
// next to its tests.

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// stubBody is the JSON shape every P2 stub returns. Centralising it
// here keeps the three handlers in lock-step so /admin tooling can
// detect "still a skeleton" by the "phase" key.
func stubBody() gin.H {
	return gin.H{
		"error": "not implemented",
		"phase": "P2-skeleton",
		"next":  "real impl lands in P3 (router) / P4 (warm-pull) / P5 (eviction)",
	}
}

// handleBlobGetStub — GET /v1/blob/:sha256. P3 will resolve sha256 →
// on-disk blob path and stream it; on cache miss it 302s to a peer
// provider (P4 warm-pull).
func (p *Plugin) handleBlobGetStub(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, stubBody())
}

// handleReceiveStub — POST /v1/receive. P3 will accept a signed
// upload from dock (multipart blob + sha256 declaration), verify,
// persist under BlobDir, and register the blob in the polar_assets DB.
func (p *Plugin) handleReceiveStub(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, stubBody())
}

// handlePullStub — POST /v1/pull. P4 will trigger an out-of-band
// warm-pull from a peer provider for a sha256 we don't yet hold.
func (p *Plugin) handlePullStub(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, stubBody())
}
