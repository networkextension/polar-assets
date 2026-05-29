// Package assets is the polar edge-cache provider plugin. Phase 2
// ships the skeleton — dock handshake, heartbeat, healthz, and route
// stubs that return HTTP 501 for /v1/{blob,receive,pull}. Real blob
// serving lands in later phases:
//
//   - P3 wires the dock-side router + signed URL minting + real
//     /v1/blob/<sha256> serving here.
//   - P4 adds warm-pull from peer providers on cache miss.
//   - P5 adds LRU eviction + disk pressure metrics.
//
// Design:
//   - Plugin → dock auth via the SDK's HMAC client (sdk.Client) using
//     the plaintext token captured at /admin-plugins.html creation.
//   - HTTP server is a plain gin engine — assets-svc's cmd/main.go
//     wires it up. The plugin doesn't manage process lifecycle.
//   - Heartbeat goroutine pings dock every 60s so /admin-plugins.html
//     shows fresh state and so plugin GC can spot dead workers.
//   - This skeleton has NO database of its own. P3 will add a
//     polar_assets DB for the blob index — see TODO in New().
package assets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/networkextension/polar-sdk"
)

// Plugin holds the runtime state for assets-svc.
type Plugin struct {
	Dock       *sdk.Client
	Name       string
	Listen     string
	Ver        string
	BlobDir        string // assets-svc-local blob root (e.g. /Users/local/assets-svc-data)
	CapacityGB     int    // soft cap for LRU eviction; 0 disables sweeper
	DockHMACSecret string // dock-side shared secret; must match the asset_providers.hmac_token row for this slug
	MetricsTok     string // Bearer token for /metrics; empty = endpoint 404

	metrics   *assetsMetrics
	startedAt time.Time
}

type Config struct {
	DockBase       string
	PluginName     string
	PluginToken    string
	Listen         string
	BuildVersion   string
	BlobDir        string
	CapacityGB     int
	DockHMACSecret string
	MetricsToken   string
}

// New builds the dock SDK client, verifies the HMAC handshake via
// /internal/v1/ping, and registers metrics. Caller must then call
// RegisterRoutes(engine) + Start(ctx).
//
// TODO(P3): add polar_assets DB for blob index (sha256 → on-disk
// path + ref-count + last-access). Until then this skeleton holds no
// persistent state of its own.
func New(ctx context.Context, cfg Config) (*Plugin, error) {
	cfg.PluginName = strings.TrimSpace(cfg.PluginName)
	if cfg.PluginName == "" {
		cfg.PluginName = "assets"
	}
	if strings.TrimSpace(cfg.DockBase) == "" {
		return nil, errors.New("assets.New: DockBase required")
	}
	if strings.TrimSpace(cfg.PluginToken) == "" {
		return nil, errors.New("assets.New: PluginToken required (plaintext from /admin-plugins.html)")
	}
	if strings.TrimSpace(cfg.BlobDir) == "" {
		return nil, errors.New("assets.New: BlobDir required (assets-svc-local data root)")
	}

	dock := sdk.NewClient(cfg.DockBase, cfg.PluginName, sdk.DeriveHMACKey(cfg.PluginToken))
	resp, err := dock.Do(http.MethodGet, "/internal/v1/ping", nil)
	if err != nil {
		return nil, fmt.Errorf("dock ping: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dock /ping rejected: HTTP %d (check PLUGIN_TOKEN + plugin_modules row)", resp.StatusCode)
	}

	_ = ctx // reserved for future DB ping (P3)

	// Log a fingerprint of the signed-URL secret at startup so an
	// operator can confirm the running process actually has the
	// right value without leaking the secret itself. Compare
	// against dock-side:
	//   psql -c "SELECT substr(encode(digest(hmac_token,'sha256'),'hex'),1,16) FROM asset_providers WHERE slug='<slug>';"
	logSecretFingerprint(cfg.PluginName, cfg.DockHMACSecret)

	return &Plugin{
		Dock:       dock,
		Name:       cfg.PluginName,
		Listen:     cfg.Listen,
		Ver:        cfg.BuildVersion,
		BlobDir:        cfg.BlobDir,
		CapacityGB:     cfg.CapacityGB,
		DockHMACSecret: cfg.DockHMACSecret,
		MetricsTok:     cfg.MetricsToken,
		metrics:    newAssetsMetrics(),
		startedAt:  time.Now(),
	}, nil
}

// RegisterRoutes attaches the assets plugin's HTTP surface to an
// existing gin engine.
//
// Public /v1/* — token / Bearer auth handled inside each handler.
// Admin /api/admin/assets-* — requireAdminViaDock middleware (Dock auth).
// /healthz + /metrics for ops.
func (p *Plugin) RegisterRoutes(r gin.IRouter) {
	r.GET("/healthz", p.handleHealthz)
	r.GET("/metrics", p.handleMetricsExposition)
	r.GET("/stats", p.handleStats)

	// /v1/* — blob-cache device-facing surface (skeletons return 501).
	v1 := r.Group("/v1")
	{
		v1.GET("/blob/:sha256", p.handleBlobGet)
		v1.POST("/receive", p.handleReceive)
		v1.POST("/pull", p.handlePull)
	}

	// /api/admin/assets-* — admin CRUD, Dock-auth-gated. P3 will add
	// real admin endpoints (list cached blobs, evict, peer mgmt). For
	// now the group exists so the middleware compiles + future routes
	// have a stable mount point.
	_ = r.Group("/api/admin", p.requireAdminViaDock())
}

// Start kicks off background work: heartbeat to dock + LRU eviction
// sweeper. P3+ will add the warm-pull worker here too.
func (p *Plugin) Start(ctx context.Context) {
	go p.heartbeatLoop(ctx)
	go p.runEvictionSweeper(ctx)
}

// Close releases plugin resources. P3 will close the DB pool here.
func (p *Plugin) Close() error {
	return nil
}
