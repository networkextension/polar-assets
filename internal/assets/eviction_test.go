package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeBlob writes a fake blob with a deterministic-but-distinct
// sha256-hex filename, sets its size + mtime, and optionally creates
// a `.pin` sidecar.
func makeBlob(t *testing.T, dir string, label string, sizeBytes int, mtime time.Time, pinned bool) string {
	t.Helper()
	// Build a sha256-looking filename derived from label so each test
	// case yields a distinct path.
	h := sha256.Sum256([]byte(label))
	name := hex.EncodeToString(h[:])
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, make([]byte, sizeBytes), 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if pinned {
		if err := os.WriteFile(path+".pin", []byte("pin"), 0o644); err != nil {
			t.Fatalf("write pin: %v", err)
		}
	}
	return name
}

func TestWalkBlobs_FiltersJunk(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	good := makeBlob(t, dir, "alpha", 100, now, false)
	// junk that should NOT show up
	_ = os.WriteFile(filepath.Join(dir, "not-a-sha"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "ABCDEF"+good[6:]), []byte("y"), 0o644) // uppercase, fails regex
	_ = os.WriteFile(filepath.Join(dir, good+".pin"), []byte("pin"), 0o644)     // sidecar
	entries, err := walkBlobs(dir)
	if err != nil {
		t.Fatalf("walkBlobs: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("walkBlobs returned %d entries; want 1 (the .pin and bad-format files should be skipped)", len(entries))
	}
	if entries[0].SHA256 != good {
		t.Errorf("walkBlobs returned %q, want %q", entries[0].SHA256, good)
	}
	if !entries[0].Pinned {
		t.Errorf("walkBlobs did not detect .pin sidecar")
	}
}

func TestEvictOnce_NoOpBelowTrigger(t *testing.T) {
	dir := t.TempDir()
	makeBlob(t, dir, "small1", 50<<20, time.Now(), false)
	p := &Plugin{BlobDir: dir, CapacityGB: 1} // 1 GB capacity, 50 MB used = 5%
	deleted, freed, err := p.evictOnce()
	if err != nil {
		t.Fatalf("evictOnce: %v", err)
	}
	if deleted != 0 || freed != 0 {
		t.Errorf("expected no-op below trigger; got deleted=%d freed=%d", deleted, freed)
	}
}

func TestEvictOnce_TrimsToTargetWhenOverTrigger(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// 1 GB capacity → trigger at 870 MB (85%), target at 716 MB (70%).
	// 10 blobs × 100 MB each = 1000 MB → over trigger. Need to delete
	// enough to fall below ~716 MB. Oldest first.
	for i := 0; i < 10; i++ {
		mtime := now.Add(-time.Duration(i) * time.Hour) // older index → older mtime is later i
		makeBlob(t, dir, fmt.Sprintf("blob%d", i), 100<<20, mtime, false)
	}
	p := &Plugin{BlobDir: dir, CapacityGB: 1}
	deleted, freed, err := p.evictOnce()
	if err != nil {
		t.Fatalf("evictOnce: %v", err)
	}
	// 1000 MB → 716 MB target means freeing >= 284 MB → at least 3 blobs.
	if deleted < 3 {
		t.Errorf("expected at least 3 deletions, got %d (freed %d MB)", deleted, freed>>20)
	}
	used, _, err := sumUsedBytes(dir)
	if err != nil {
		t.Fatalf("sumUsedBytes: %v", err)
	}
	target := int64(1) << 30 * 70 / 100
	if used > target {
		t.Errorf("used %d MB > target %d MB; sweeper didn't reach target", used>>20, target>>20)
	}
}

func TestEvictOnce_RespectsPinMarkers(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// 5 blobs, all 200 MB. The 3 oldest are pinned, the 2 youngest are
	// evictable. Total = 1000 MB; capacity = 1 GB; over trigger.
	// Pinned blobs should NOT be deleted even though they're older.
	pinnedSet := map[string]struct{}{}
	for i := 0; i < 5; i++ {
		mtime := now.Add(-time.Duration(5-i) * time.Hour) // i=0 oldest, i=4 youngest
		isPinned := i < 3
		name := makeBlob(t, dir, fmt.Sprintf("blob%d", i), 200<<20, mtime, isPinned)
		if isPinned {
			pinnedSet[name] = struct{}{}
		}
	}
	p := &Plugin{BlobDir: dir, CapacityGB: 1}
	_, _, err := p.evictOnce()
	if err != nil {
		t.Fatalf("evictOnce: %v", err)
	}
	// All 3 pinned files must still exist.
	for name := range pinnedSet {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("pinned blob %q got deleted: %v", name, err)
		}
	}
}

func TestSumUsedBytes_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	total, count, err := sumUsedBytes(dir)
	if err != nil {
		t.Fatalf("sumUsedBytes: %v", err)
	}
	if total != 0 || count != 0 {
		t.Errorf("empty dir → got total=%d count=%d, want 0/0", total, count)
	}
}

func TestSumUsedBytes_MissingDir(t *testing.T) {
	total, count, err := sumUsedBytes("/path/does/not/exist/xyzzy")
	if err != nil {
		t.Fatalf("expected nil err on missing dir, got %v", err)
	}
	if total != 0 || count != 0 {
		t.Errorf("missing dir → got total=%d count=%d, want 0/0", total, count)
	}
}
