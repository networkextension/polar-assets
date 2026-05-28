// Command assets-svc is the polar edge-cache provider plugin binary.
// This Phase 2 build is a skeleton — /healthz + dock heartbeat +
// route stubs for /v1/{blob,receive,pull}. Real blob serving lands in
// later phases (P3 router + P4 warm-pull + P5 eviction).
//
// Env vars:
//
//	POLAR_DOCK_BASE             http://127.0.0.1:8080
//	POLAR_PLUGIN_NAME           assets             (matches plugin_modules row)
//	POLAR_PLUGIN_TOKEN          polar_plugin_…     (plaintext from /admin-plugins.html)
//	POLAR_ASSETS_LISTEN         127.0.0.1:8091     (HTTP listen addr)
//	POLAR_ASSETS_VERSION        git-sha or "0.0.1" (cosmetic; appears in /admin-plugins.html)
//	POLAR_ASSETS_BLOB_DIR       /Users/local/assets-svc-data
//	POLAR_ASSETS_CAPACITY_GB    100   (soft cap for LRU eviction; 0 disables sweeper)
//	POLAR_ASSETS_METRICS_TOKEN  bearer token for /metrics; unset = endpoint 404
//
// The plaintext PLUGIN_TOKEN is stored ONLY in the plugin's env (chmod
// 600 .env file recommended). Dock never sees it after creation —
// only the sha256 hash in plugin_modules.plugin_key_hash.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/networkextension/polar-assets/internal/assets"
)

func main() {
	cfg := assets.Config{
		DockBase:     envOrDefault("POLAR_DOCK_BASE", "http://127.0.0.1:8080"),
		PluginName:   envOrDefault("POLAR_PLUGIN_NAME", "assets"),
		PluginToken:  os.Getenv("POLAR_PLUGIN_TOKEN"),
		Listen:       envOrDefault("POLAR_ASSETS_LISTEN", "127.0.0.1:8091"),
		BuildVersion: envOrDefault("POLAR_ASSETS_VERSION", "0.0.1"),
		BlobDir:      envOrDefault("POLAR_ASSETS_BLOB_DIR", "/Users/local/assets-svc-data"),
		CapacityGB:     envIntOrDefault("POLAR_ASSETS_CAPACITY_GB", 100),
		DockHMACSecret: os.Getenv("POLAR_ASSETS_DOCK_HMAC_SECRET"),
		MetricsToken:   os.Getenv("POLAR_ASSETS_METRICS_TOKEN"),
	}
	if strings.TrimSpace(cfg.DockHMACSecret) == "" {
		log.Print("WARNING: POLAR_ASSETS_DOCK_HMAC_SECRET unset — /v1/blob + /v1/receive will 401/403 every request. Set it BEFORE registering the provider with dock.")
	}
	if strings.TrimSpace(cfg.PluginToken) == "" {
		log.Fatal("POLAR_PLUGIN_TOKEN unset — get plaintext from /admin-plugins.html (one-time print at row creation)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	plugin, err := assets.New(ctx, cfg)
	if err != nil {
		log.Fatalf("assets.New: %v", err)
	}
	defer plugin.Close()

	gin.SetMode(envOrDefault("GIN_MODE", gin.ReleaseMode))
	r := gin.New()
	r.Use(gin.Recovery())
	plugin.RegisterRoutes(r)
	plugin.Start(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("assets-svc listening on %s (dock=%s, name=%s, ver=%s)",
			cfg.Listen, cfg.DockBase, cfg.PluginName, cfg.BuildVersion)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("assets-svc: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("assets-svc: shutdown: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envIntOrDefault(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Printf("env %s=%q is not a valid int; using fallback %d", key, v, fallback)
		return fallback
	}
	return n
}
