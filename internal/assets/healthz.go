package assets

// healthz.go — /healthz endpoint. The Phase 2 skeleton has no DB or
// downstream of its own to probe, so this is a simple liveness ping
// (process up + uptime). P3 will extend with a polar_assets DB ping
// + blob-dir writability check.

import (
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
)

func (p *Plugin) handleHealthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"ok":             true,
		"name":           p.Name,
		"version":        p.Ver,
		"uptime_seconds": int64(time.Since(p.startedAt).Seconds()),
		"go":             runtime.Version(),
	})
}
