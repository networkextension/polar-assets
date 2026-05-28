package assets

// eviction.go — periodic LRU sweeper. Triggers when used > 85% of
// capacity; deletes oldest-mtime-first (non-pinned) until usage
// falls under 70%. Logs every delete at INFO so an operator can
// reconstruct decisions from the log.
//
// Why those numbers: 85% leaves enough headroom for several large
// writes between sweeper ticks; 70% is a "comfortable" target that
// prevents the sweeper from running back-to-back as soon as the
// next blob lands. Tunable later if real-world traffic disagrees.

import (
	"context"
	"log"
	"os"
	"sort"
	"time"
)

const (
	evictionInterval   = 5 * time.Minute
	evictionTriggerPct = 85
	evictionTargetPct  = 70
)

// runEvictionSweeper is the goroutine entry. Loops every
// evictionInterval, calls evictOnce, logs the outcome. Returns when
// ctx is done. Caller wires from Plugin.Start().
//
// Disabled when CapacityGB <= 0; useful for boxes where the operator
// wants the sweeper off (e.g. dev box with infinite disk).
func (p *Plugin) runEvictionSweeper(ctx context.Context) {
	if p.CapacityGB <= 0 {
		log.Print("assets: eviction sweeper disabled (CapacityGB <= 0)")
		return
	}
	log.Printf("assets: eviction sweeper enabled (capacity=%dGB, interval=%v, trigger=%d%%, target=%d%%)",
		p.CapacityGB, evictionInterval, evictionTriggerPct, evictionTargetPct)
	// One immediate sweep so a freshly-restarted instance with bloated
	// cache gets trimmed without waiting an interval.
	p.evictOnceLogged()
	t := time.NewTicker(evictionInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.evictOnceLogged()
		}
	}
}

// evictOnceLogged wraps evictOnce with structured logging at the
// end so the goroutine's outcome is visible without each call site
// having to format it.
func (p *Plugin) evictOnceLogged() {
	deleted, freed, err := p.evictOnce()
	if err != nil {
		log.Printf("assets: eviction sweep error: %v", err)
		return
	}
	if deleted == 0 {
		return // no log noise when there's nothing to do
	}
	log.Printf("assets: eviction sweep deleted %d blobs, freed %.2f GB", deleted, float64(freed)/float64(1<<30))
}

// evictOnce trims the cache to evictionTargetPct of capacity when
// usage > evictionTriggerPct. Returns (deletedCount, freedBytes, err).
// Honors `.pin` sidecars — pinned blobs are never deleted, even if
// it means failing to reach the target (in which case we log a
// warning and return with what we managed).
func (p *Plugin) evictOnce() (int, int64, error) {
	entries, err := walkBlobs(p.BlobDir)
	if err != nil {
		return 0, 0, err
	}
	var used int64
	for _, e := range entries {
		used += e.Size
	}
	capacityBytes := int64(p.CapacityGB) << 30
	trigger := capacityBytes * evictionTriggerPct / 100
	target := capacityBytes * evictionTargetPct / 100
	if used <= trigger {
		return 0, 0, nil
	}
	// Sort oldest-first so the LRU victim is index 0.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ModTime.Before(entries[j].ModTime)
	})
	var (
		deleted int
		freed   int64
	)
	for _, e := range entries {
		if used <= target {
			break
		}
		if e.Pinned {
			continue
		}
		if err := os.Remove(e.Path); err != nil {
			log.Printf("assets: eviction failed to delete %s: %v", e.Path, err)
			continue
		}
		log.Printf("assets: evicted blob sha=%s size=%d age=%v",
			e.SHA256, e.Size, time.Since(e.ModTime).Round(time.Second))
		used -= e.Size
		freed += e.Size
		deleted++
	}
	if used > target {
		log.Printf("assets: eviction couldn't reach target — used=%d > target=%d; pinned bytes likely dominate. consider raising capacity or unpinning",
			used, target)
	}
	return deleted, freed, nil
}
