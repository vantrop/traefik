package tls

import (
	"crypto/x509"
	"fmt"

	"github.com/rs/zerolog/log"
)

type crlSnaphotProvider interface {
	// get a snapshot from a store for a DP using it's issuer
	getVerifiedSnapshot(store *CRLStore, distributionPoint string, issuer *x509.Certificate) (crlSnapshot, error)
}

// CRL loaded through HTTP should be refreshed by the first request using it,
// other requests will be using stale data
type openSnaphotProvider struct {
	clientHolder *crlHTTPClientHolder
}

func (p *openSnaphotProvider) getVerifiedSnapshot(store *CRLStore, distributionPoint string, issuer *x509.Certificate) (crlSnapshot, error) {
	entry := store.getOrCreateEntry(distributionPoint)
	snap := entry.snapshot()

	// new entry
	if snap == nil {
		entry.refreshMu.Lock()
		defer entry.refreshMu.Unlock()
		// check if entry has been loaded by another goroutine
		if entry.snapshot() != nil {
			return snap, nil
		}
		// new entry --> set loader to HTTP
		entry.loader = &crlHTTPLoader{
			distributionPoint: distributionPoint,
			issuer:            issuer,
			clientHolder:      p.clientHolder,
		}
		if err := entry.reload(distributionPoint); err != nil {
			log.Warn().
				Str("distributionPoint", distributionPoint).
				Msgf("could not load CRL %s, %v", distributionPoint, err)
		}
		snap = entry.snapshot()

	} else {
		// existing entry
		if snap.needsRefresh(store.crlReloadInterval) {
			if !entry.refreshMu.TryLock() {
				// if couldn't lock, use stale entry
				return snap, nil
			}
			// lock and reload
			defer entry.refreshMu.Unlock()
			snap = entry.snapshot()
			// check if reloaded by another goroutine
			if !snap.needsRefresh(store.crlReloadInterval) {
				return snap, nil
			}
			if err := entry.reload(distributionPoint); err != nil {
				log.Warn().
					Str("distributionPoint", distributionPoint).
					Msgf("could not refresh CRL %s, using stale data: %v", distributionPoint, err)
			}
			snap = entry.snapshot()
		}
	}

	if snap == nil {
		return nil, fmt.Errorf("no valid CRL snapshot available")
	}

	return snap, nil
}

// CRL loaded through HTTP should be refreshed by the first request using it,
// other requests will be locked (expect high latency burst)
type failedCloseSnapshotProvider struct {
	clientHolder *crlHTTPClientHolder
}

func (p *failedCloseSnapshotProvider) getVerifiedSnapshot(store *CRLStore, distributionPoint string, issuer *x509.Certificate) (crlSnapshot, error) {
	entry := store.getOrCreateEntry(distributionPoint)

	// Chemin rapide : snapshot présent et encore frais → lecture lock-free.
	snap := entry.snapshot()
	if snap != nil && !snap.needsRefresh(store.crlReloadInterval) {
		return snap, nil
	}

	// Absent or expired snaphot, mandatory blocking refresh
	// All goroutines will wait here
	entry.refreshMu.Lock()
	defer entry.refreshMu.Unlock()

	// check if reloaded by another goroutine
	snap = entry.snapshot()
	if snap != nil && !snap.needsRefresh(store.crlReloadInterval) {
		return snap, nil
	}

	if snap == nil {
		// new entry set loader
		entry.loader = &crlHTTPLoader{
			distributionPoint: distributionPoint,
			issuer:            issuer,
			clientHolder:      p.clientHolder,
		}
	}

	if err := entry.reload(distributionPoint); err != nil {
		// Fail-closed : do not return expired snap
		return nil, fmt.Errorf("%s: %v", "CRL is stale or missing and could not be refreshed", err)
	}

	// updated snapshot
	return entry.snapshot(), nil
}
