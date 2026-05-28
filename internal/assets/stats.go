package assets

// stats.go — GET /stats. Real (non-stub) handler returning the
// current cache footprint. Bearer-token gated via MetricsTok using
// the same pattern as /metrics — when MetricsTok is empty the
// endpoint returns 404 so unauthorized probers don't even learn it
// exists.

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// statsResponse is what GET /stats returns. Sizes are in GB
// (float) for human readability; counts are ints.
type statsResponse struct {
	UsedGB       float64 `json:"used_gb"`
	CapacityGB   int     `json:"capacity_gb"`
	UsagePct     float64 `json:"usage_pct"`
	ItemCount    int     `json:"item_count"`
	PinnedCount  int     `json:"pinned_count"`
	OldestAgeSec int64   `json:"oldest_age_sec,omitempty"`
	NewestAgeSec int64   `json:"newest_age_sec,omitempty"`
}

func (p *Plugin) handleStats(c *gin.Context) {
	if strings.TrimSpace(p.MetricsTok) == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	auth := strings.TrimSpace(c.GetHeader("Authorization"))
	expected := "Bearer " + p.MetricsTok
	if auth != expected {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid bearer"})
		return
	}
	entries, err := walkBlobs(p.BlobDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "walk failed"})
		return
	}
	var (
		used        int64
		pinned      int
		oldest      time.Time
		newest      time.Time
		oldestValid bool
	)
	for _, e := range entries {
		used += e.Size
		if e.Pinned {
			pinned++
		}
		if !oldestValid || e.ModTime.Before(oldest) {
			oldest = e.ModTime
			oldestValid = true
		}
		if e.ModTime.After(newest) {
			newest = e.ModTime
		}
	}
	resp := statsResponse{
		UsedGB:      float64(used) / float64(1<<30),
		CapacityGB:  p.CapacityGB,
		ItemCount:   len(entries),
		PinnedCount: pinned,
	}
	if p.CapacityGB > 0 {
		resp.UsagePct = 100.0 * float64(used) / float64(int64(p.CapacityGB)<<30)
	}
	if oldestValid {
		resp.OldestAgeSec = int64(time.Since(oldest).Seconds())
		resp.NewestAgeSec = int64(time.Since(newest).Seconds())
	}
	c.JSON(http.StatusOK, resp)
}
