package crlenforcer

import (
	"crypto/x509"
	"fmt"
	"log"
	"time"
)

// IMPLEM Open, en cas de crl indisponnible, ne fail pas, utilise les crl mis en cache
type OpenSnapshotManager struct {
	DownloadableCrlManager
}

// getVerifiedSnapshot retourne un snapshot CRL garanti signé par `issuer`
// et temporellement valide, en rafraîchissant le cache si nécessaire.
func (m *OpenSnapshotManager) getVerifiedSnapshot(uri string, issuer *x509.Certificate) (*crlSnapshot, error) {
	entry, _ := m.getOrCreateEntry(uri)
	snap := entry.snapshot()

	if snap == nil || snap.needsRefresh(m.RefreshInterval) {
		if err := m.refreshVerifiedEntry(entry, uri, issuer); err != nil {
			if snap == nil {
				return nil, err
			}
			log.Printf("[crlenforcer] WARNING: could not refresh CRL %q, using stale data: %v", uri, err)
		}
		snap = entry.snapshot()
	}

	if snap == nil {
		return nil, fmt.Errorf("no valid CRL snapshot available")
	}

	return snap, nil
}

// refreshVerifiedEntry télécharge, vérifie (signature + fraîcheur + anti-
// rollback) puis stocke le nouveau snapshot.
func (m *OpenSnapshotManager) refreshVerifiedEntry(entry *crlEntry, uri string, issuer *x509.Certificate) error {
	old := entry.snapshot()

	if old == nil {
		entry.refreshMu.Lock()
		defer entry.refreshMu.Unlock()
		if entry.snapshot() != nil {
			return nil
		}
	} else {
		if !entry.refreshMu.TryLock() {
			return nil
		}
		defer entry.refreshMu.Unlock()
		if !entry.snapshot().needsRefresh(m.RefreshInterval) {
			return nil
		}
	}

	raw, err := m.downloadCRL(uri)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	crl, err := parseCRL(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	// ── Vérifications de sécurité obligatoires ──────────────────────────────
	if err := verifyCRLSignature(crl, issuer); err != nil {
		return err
	}
	if err := verifyCRLFreshness(crl, time.Now()); err != nil {
		return err
	}
	if old != nil {
		if err := verifyCRLNumberMonotonic(crl, old.crl); err != nil {
			return err
		}
	}
	// ─────────────────────────────────────────────────────────────────────

	revokedSerials := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	for _, rev := range crl.RevokedCertificateEntries {
		revokedSerials[rev.SerialNumber.String()] = struct{}{}
	}

	entry.storeSnapshot(&crlSnapshot{
		crl:            crl,
		revokedSerials: revokedSerials,
		modTime:        time.Now(),
	})

	log.Printf("[crlenforcer] CRL %s refreshed: %d revoked entries, next update: %s",
		uri, len(revokedSerials), crl.NextUpdate.Format(time.RFC3339))

	return nil
}
