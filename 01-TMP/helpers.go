package crlenforcer

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

func parseCRL(raw []byte) (*x509.RevocationList, error) {
	if crl, err := x509.ParseRevocationList(raw); err == nil {
		return crl, nil
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("data is neither valid DER nor PEM")
	}
	return x509.ParseRevocationList(block.Bytes)
}

// ---------------------------------------------------------------------------
// Vérification cryptographique du CRL
// ---------------------------------------------------------------------------

// verifyCRLSignature vérifie que la CRL a bien été signée par l'émetteur
// attendu, empêchant toute falsification par un tiers contrôlant le endpoint HTTP.
func verifyCRLSignature(crl *x509.RevocationList, issuer *x509.Certificate) error {
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL signature verification failed: %w", err)
	}

	// L'Issuer déclaré dans la CRL doit correspondre au certificat émetteur réel.
	if crl.Issuer.String() != issuer.Subject.String() {
		return fmt.Errorf("CRL issuer mismatch: got %q, expected %q",
			crl.Issuer.String(), issuer.Subject.String())
	}

	return nil
}

// verifyCRLFreshness vérifie la fenêtre de validité temporelle de la CRL et
// empêche l'utilisation d'une CRL antidatée ou "du futur".
func verifyCRLFreshness(crl *x509.RevocationList, now time.Time) error {
	if now.Before(crl.ThisUpdate) {
		return fmt.Errorf("CRL thisUpdate is in the future: %s", crl.ThisUpdate)
	}
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return fmt.Errorf("CRL has expired: nextUpdate was %s", crl.NextUpdate)
	}
	return nil
}

// verifyCRLNumberMonotonic empêche le rejeu d'une CRL antérieure (rollback
// attack) en s'assurant que le CRLNumber ne régresse jamais.
func verifyCRLNumberMonotonic(newCRL, oldCRL *x509.RevocationList) error {
	if oldCRL == nil || oldCRL.Number == nil || newCRL.Number == nil {
		return nil // pas de référence précédente, ou CA n'utilise pas CRLNumber
	}
	if newCRL.Number.Cmp(oldCRL.Number) < 0 {
		return fmt.Errorf("CRL rollback detected: new number %s < cached number %s",
			newCRL.Number, oldCRL.Number)
	}
	return nil
}
