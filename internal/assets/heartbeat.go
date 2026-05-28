package assets

// heartbeat.go — 60s loop that POSTs to dock's
// /internal/v1/plugin-registry/heartbeat so /admin-plugins.html shows
// this svc as alive and the dynamic sidebar source picks up our
// UIRoutes contribution.

import (
	"context"
	"log"
	"time"

	"github.com/networkextension/polar-sdk"
)

// assetsUIRoutes — sidebar entries this plugin contributes. The
// /assets.html page is delivered by the future polar-assets-ui (P6);
// declaring it here at P2 lets dock paint the entry as soon as the
// plugin row exists.
var assetsUIRoutes = []sdk.UIRoute{
	{Path: "/assets.html", Label: "文件管理", Icon: "file", AdminOnly: false, Order: 80},
}

// heartbeatLoop pings dock once at startup, then every 60s. Failures
// log + continue; dock's plugin GC tolerates one missed beat.
func (p *Plugin) heartbeatLoop(ctx context.Context) {
	p.beat(ctx)
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.beat(ctx)
		}
	}
}

func (p *Plugin) beat(_ context.Context) {
	err := p.Dock.Heartbeat(sdk.HeartbeatOpts{
		Version:       p.Ver,
		Endpoint:      p.Listen,
		UptimeSeconds: int64(time.Since(p.startedAt).Seconds()),
		UIRoutes:      assetsUIRoutes,
	})
	if err != nil {
		log.Printf("assets: heartbeat failed: %v", err)
	}
}
