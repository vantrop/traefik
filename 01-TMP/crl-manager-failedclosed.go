package crlenforcer

import (
	"crypto/x509"
	"fmt"
	"log"
	"time"
)

type FaileClosedSnapshotManager struct {
	DownloadableCrlManager
}

// ---------------------------------------------------------------------------
// getVerifiedSnapshot – refresh bloquant, fail-closed strict
// ---------------------------------------------------------------------------

// getVerifiedSnapshot retourne un snapshot CRL garanti frais et vérifié.
//
// Contrairement à une implémentation "fail-open", cette version ne retombe
// JAMAIS sur des données périmées en cas d'échec de rafraîchissement : soit
// le refresh réussit et le nouveau snapshot est retourné, soit il échoue et
// une erreur est propagée à l'appelant, qui doit alors rejeter la requête.
func (m *FaileClosedSnapshotManager) getVerifiedSnapshot(uri string, issuer *x509.Certificate) (*crlSnapshot, error) {
	entry, _ := m.getOrCreateEntry(uri)

	// Chemin rapide : snapshot présent et encore frais → lecture lock-free.
	snap := entry.snapshot()
	if snap != nil && !snap.needsRefresh(m.RefreshInterval) {
		return snap, nil
	}

	// Snapshot absent ou périmé : refresh obligatoire et bloquant.
	// Toutes les goroutines concurrentes pour cette URI attendent ici ;
	// une seule effectue réellement l'appel réseau.
	entry.refreshMu.Lock()
	defer entry.refreshMu.Unlock()

	// Double-check : une autre goroutine a peut-être déjà rafraîchi l'entrée
	// pendant qu'on attendait le verrou.
	snap = entry.snapshot()
	if snap != nil && !snap.needsRefresh(m.RefreshInterval) {
		return snap, nil
	}

	if err := m.fetchVerifyAndStore(entry, uri, issuer); err != nil {
		// Fail-closed : on ne retourne JAMAIS l'ancien snapshot périmé ici.
		return nil, fmt.Errorf("%w: %v", ErrCRLUnavailable, err)
	}

	return entry.snapshot(), nil
}

// fetchVerifyAndStore télécharge, vérifie cryptographiquement (signature,
// fraîcheur, anti-rollback) puis stocke le nouveau snapshot.
// Doit être appelée avec entry.refreshMu tenu.
func (m *FaileClosedSnapshotManager) fetchVerifyAndStore(entry *crlEntry, uri string, issuer *x509.Certificate) error {
	old := entry.snapshot() // référence pour le contrôle anti-rollback

	raw, err := m.downloadCRL(uri)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	crl, err := parseCRL(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

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
