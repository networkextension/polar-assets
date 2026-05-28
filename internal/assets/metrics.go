package assets

// metrics.go — assets-svc's own Prometheus registry. Phase 2 scaffold:
// a single counter `polar_assets_requests_total{route,status}` so the
// /metrics endpoint isn't empty and dashboards can wire up scrape jobs
// before P3 lands. P3 will add cache hit/miss + warm-pull latency etc.

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type assetsMetrics struct {
	registry *prometheus.Registry

	requestsTotal *prometheus.CounterVec // labels: route, status
}

func newAssetsMetrics() *assetsMetrics {
	m := &assetsMetrics{registry: prometheus.NewRegistry()}
	m.requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "polar_assets_requests_total",
			Help: "Total HTTP requests served by assets-svc, by route + status. P3 will start incrementing in handlers.",
		},
		[]string{"route", "status"},
	)
	m.registry.MustRegister(m.requestsTotal)
	return m
}

// recordRequest is the canonical incrementer for the request counter.
// P3 handlers will call this after writing each response. Kept as a
// helper so the label cardinality stays bounded (route is a static
// template, not the raw path).
func (m *assetsMetrics) recordRequest(route, status string) {
	if m == nil {
		return
	}
	if route == "" {
		route = "unknown"
	}
	if status == "" {
		status = "unknown"
	}
	m.requestsTotal.WithLabelValues(route, status).Inc()
}

// handleMetricsExposition is the Prometheus scrape endpoint. Same
// token-gate pattern as dock + polar-wg: empty MetricsTok = 404 the
// endpoint entirely (refuse to expose internals); set the env var
// to opt in.
func (p *Plugin) handleMetricsExposition(c *gin.Context) {
	if p.MetricsTok == "" {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if c.GetHeader("Authorization") != "Bearer "+p.MetricsTok {
		c.Header("WWW-Authenticate", `Bearer realm="metrics"`)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	promhttp.HandlerFor(p.metrics.registry, promhttp.HandlerOpts{}).ServeHTTP(c.Writer, c.Request)
}
