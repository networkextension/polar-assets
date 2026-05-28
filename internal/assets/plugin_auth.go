package assets

// plugin_auth.go — verifyPluginSig validates the X-Polar-Plugin-*
// HMAC headers that polar-dock attaches to /v1/receive requests
// (and any other write-side endpoints we add). Mirrors dock's
// hmacPluginAuth middleware on the receiving end.
//
// Canonical string the sender signed:
//
//	<METHOD>\n<PATH>\n<TIMESTAMP>\n<HEX_SHA256_OF_BODY>
//
// Key bytes = our DockHMACSecret (must match
// asset_providers.hmac_token in the dock DB; same value the
// admin saved when creating the provider row).
//
// Skew tolerance: 5 minutes either way on the timestamp. Tighter
// would require ntp sync between dock + provider; looser would let
// captured requests get replayed. Five min is the same window
// dock's plugin auth uses.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxPluginAuthSkew = 5 * time.Minute
)

// verifyPluginSig consumes the request body, verifies sig, and
// returns the body bytes for the handler to re-parse (since
// http.Request.Body is single-read). On any failure returns the
// category in the error — caller should respond 401 with a generic
// message, not the failure detail.
func verifyPluginSig(req *http.Request, secret []byte) ([]byte, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	if len(secret) == 0 {
		return nil, errors.New("missing secret")
	}
	sig := req.Header.Get("X-Polar-Plugin-Sig")
	ts := req.Header.Get("X-Polar-Plugin-Timestamp")
	name := req.Header.Get("X-Polar-Plugin-Name")
	if sig == "" || ts == "" || name == "" {
		return nil, errors.New("missing plugin headers")
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, errors.New("bad ts")
	}
	skew := time.Since(time.Unix(tsInt, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > maxPluginAuthSkew {
		return nil, errors.New("ts skew too large")
	}
	// Cap the read so a malicious peer can't OOM us with a 100GB
	// body during sig-check. 6 GB is comfortably above our v1 single-
	// upload ceiling of 5 GB; tighten when chunked upload lands.
	body, err := io.ReadAll(io.LimitReader(req.Body, 6<<30))
	if err != nil {
		return nil, err
	}
	bodySum := sha256.Sum256(body)
	canonical := strings.ToUpper(req.Method) + "\n" + req.URL.Path + "\n" + ts + "\n" + hex.EncodeToString(bodySum[:])
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(sig)
	if err != nil {
		return nil, errors.New("bad sig hex")
	}
	if !hmac.Equal(want, got) {
		return nil, errors.New("bad sig")
	}
	// Hand the body back as a fresh reader so the handler can
	// re-parse the multipart frames.
	req.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}
