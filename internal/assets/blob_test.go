package assets

import "testing"

// TestMimeRE locks the ?ct= validation: real media mimes pass; anything that
// could split the header or smuggle params/junk is rejected (→ octet-stream).
func TestMimeRE(t *testing.T) {
	good := []string{
		"audio/mpeg", "audio/mp4", "audio/flac", "audio/x-m4a", "audio/ogg",
		"video/mp4", "image/jpeg", "image/png", "application/pdf",
	}
	for _, m := range good {
		if !mimeRE.MatchString(m) {
			t.Errorf("expected %q to be accepted", m)
		}
	}
	bad := []string{
		"", "application/octet-stream\r\nSet-Cookie: x=1", "audio/mpeg; charset=x",
		"text/html ", " audio/mpeg", "audio /mpeg", "notamime", "audio/", "/mpeg",
		"audio/mpeg\n", "<script>", "*/*",
	}
	for _, m := range bad {
		if mimeRE.MatchString(m) {
			t.Errorf("expected %q to be rejected", m)
		}
	}
}
