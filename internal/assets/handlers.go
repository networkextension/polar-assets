package assets

// handlers.go — P3 wires the real /v1/blob and /v1/receive impls
// (in blob.go + receive.go) but the route-binding lives in
// plugin.go's RegisterRoutes. This file now just keeps the
// /v1/pull stub until P4 lands warm-pull.

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// handlePullStub — POST /v1/pull. P4 will trigger an out-of-band
// warm-pull from a peer provider for a sha256 we don't yet hold.
func (p *Plugin) handlePullStub(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "not implemented",
		"phase": "P3-shipped-blob-receive",
		"next":  "warm-pull lands in P4",
	})
}
