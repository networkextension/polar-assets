package assets

// cache.go — filesystem cache view. The skeleton has no DB; eviction
// and stats both derive everything they need from walking BlobDir.
// P3 may swap to a DB-backed last_used_at if it turns out file mtime
// is insufficient (Windows quirks, fs that doesn't update on read,
// etc.) — for now mtime is "last touched" proxy and pin status is
// the presence of a sibling `<sha256>.pin` file.

import (
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// blobEntry is one cached blob's metadata derived from the
// filesystem. We capture mtime + size at walk time; both are stale
// the moment they're read, but eviction is best-effort anyway.
type blobEntry struct {
	SHA256  string
	Path    string
	Size    int64
	ModTime time.Time
	Pinned  bool
}

// sha256Re is the strict sha256-hex filename matcher. .pin sidecars
// and any unrelated junk fall through. P3 may relax this to allow
// sub-directory sharding (e.g. <sha[:2]>/<sha>) — at that point this
// regex still matches the basename and the walk needs to recurse.
var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// walkBlobs lists every blob under blobDir, capturing size + mtime
// + pin status. Single-level walk for v1 (no recursion). Silently
// skips files that don't look like sha256 hex digests; that drops
// the `.pin` sidecars + any operator-tossed junk.
func walkBlobs(blobDir string) ([]blobEntry, error) {
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]blobEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !sha256Re.MatchString(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(blobDir, name)
		_, pinErr := os.Stat(path + ".pin")
		out = append(out, blobEntry{
			SHA256:  name,
			Path:    path,
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Pinned:  pinErr == nil,
		})
	}
	return out, nil
}

// sumUsedBytes is the cheap "how full are we" calc — sum of every
// blob's size, excluding sidecars + junk. Used by /stats and as the
// pre-check in eviction so we can early-return without sorting.
func sumUsedBytes(blobDir string) (int64, int, error) {
	entries, err := walkBlobs(blobDir)
	if err != nil {
		return 0, 0, err
	}
	var total int64
	for _, e := range entries {
		total += e.Size
	}
	return total, len(entries), nil
}
