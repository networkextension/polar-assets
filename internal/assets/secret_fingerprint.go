package assets

// secret_fingerprint.go — startup diagnostic: log a non-reversible
// SHA256(secret)[:16] fingerprint of the running process's
// signed-URL secret so an operator can verify it matches what dock
// has in asset_providers.hmac_token, without ever transmitting or
// logging the secret itself.

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
)

func logSecretFingerprint(slug, secret string) {
	if secret == "" {
		log.Printf("assets: WARNING POLAR_ASSETS_DOCK_HMAC_SECRET is empty — every signed-URL verify will 403 'missing secret'. slug=%q", slug)
		return
	}
	sum := sha256.Sum256([]byte(secret))
	fp := hex.EncodeToString(sum[:])[:16]
	log.Printf("assets: signed-URL secret loaded slug=%s sha256_fp=%s len=%d (compare against `SELECT substr(encode(digest(hmac_token,'sha256'),'hex'),1,16) FROM asset_providers WHERE slug='%s';`)", slug, fp, len(secret), slug)
}
