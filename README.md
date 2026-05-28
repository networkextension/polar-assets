# polar-assets

Edge-cache provider plugin for Polar asset store.

## Status

**Phase 2 skeleton** — `/v1/{blob,receive,pull}` handlers return HTTP 501
with `{"error":"not implemented","phase":"P2-skeleton"}` until P3/P4/P5
ship the real impl. The skeleton already runs end-to-end: dock handshake,
60s heartbeat, `/healthz`, `/metrics` scaffold, launchd plist.

## Install

Standalone deploy on macOS (launchd):

```bash
# build for the target box
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o /tmp/assets-svc ./cmd/assets-svc

# rsync to box
rsync -avz /tmp/assets-svc local@<deploy-box>:/Users/local/.local/bin/

# on the box:
cp scripts/launchd/assets-svc.env.sample ~/assets-svc.env  # edit secrets
chmod 600 ~/assets-svc.env
bash scripts/launchd/setup-assets-svc.sh
```

## Environment

See `scripts/launchd/assets-svc.env.sample` for the full template.

| Var | Default | Purpose |
| --- | --- | --- |
| `POLAR_DOCK_BASE` | `http://127.0.0.1:8080` | Dock HTTP base URL for SDK calls. |
| `POLAR_PLUGIN_NAME` | `assets` | Must match `plugin_modules.name` on dock. |
| `POLAR_PLUGIN_TOKEN` | _(required)_ | Plaintext token from `/admin-plugins.html` (one-time print). |
| `POLAR_ASSETS_LISTEN` | `127.0.0.1:8091` | HTTP bind addr. nginx proxies public traffic here. |
| `POLAR_ASSETS_VERSION` | `0.0.1` | Cosmetic; stamped on `plugin_modules.version`. |
| `POLAR_ASSETS_BLOB_DIR` | `/Users/local/assets-svc-data` | On-disk blob cache root (P3+). |
| `POLAR_ASSETS_METRICS_TOKEN` | _(unset)_ | Bearer for `/metrics`; unset = endpoint 404. |

## Architecture

Pairs with `polar-dock`'s `/api/assets` catalog: dock owns the asset
metadata (sha256 + ACL + ref-counts) and signs short-lived URLs that
302 to this svc's `/v1/blob/<sha256>` endpoint. assets-svc is the
**edge-cache provider** — it serves the bytes, warm-pulls from peer
providers on miss, and runs LRU eviction. Plugin → dock auth uses the
HMAC client from
[`github.com/networkextension/polar-sdk`](https://github.com/networkextension/polar-sdk).
Full design lives in
[`polar-dock/doc/arch/assets-module.md`](https://github.com/networkextension/polar-dock/blob/main/doc/arch/assets-module.md).

## Related

- [polar-dock](https://github.com/networkextension/polar-dock) — owns the asset catalog + signs URLs
- [polar-sdk](https://github.com/networkextension/polar-sdk) — HMAC client + heartbeat
- [polar-wg](https://github.com/networkextension/polar-wg) — sibling plugin this skeleton mirrors

## License

MIT
