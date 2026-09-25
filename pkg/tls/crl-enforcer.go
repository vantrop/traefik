package tls

import (
	"crypto/x509"
	"fmt"
	"slices"
)

// Enforce CRL validation against certificates

type CRLEnforcer interface {
	// Checks a whole validated certificate chain against the associated CRls
	//
	// chain[0] is the leaf certificate, chain[len-1] should be the root CA (wich is self signed and thus cannot have CRL)
	IsChainAllowed(chain []*x509.Certificate) (bool, error)
}

// enforcer that does nothing
type crlEnforcerNOOP struct {
}

// All chains are allowed for NOOP enforcer
func (e *crlEnforcerNOOP) IsChainAllowed(chain []*x509.Certificate) (bool, error) {
	return true, nil
}

//////////////////////
//
//   Lax enforcer
//
//////////////////////

type crlEnforcerLax struct {
	whitelistEnabled             bool
	AllowedCRLDistributionPoints []string
	// local http based store
	store *CRLStore
	// global store with file based CRLs
	globalStore     *CRLStore
	snaphotProvider crlSnaphotProvider
}

// Unexpired certificates and certificates without crl definitions are allowed
func (e *crlEnforcerLax) IsChainAllowed(chain []*x509.Certificate) (bool, error) {
	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		issuer := chain[i+1] // emitter, validated by TLS handshake

		allowed, err := e.isCertAllowedAgainstIssuer(cert, issuer)
		if err != nil {
			return false, fmt.Errorf("checking cert CN=%q: %w", cert.Subject.CommonName, err)
		}
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}

// Check wether a single certificate is allowed
func (e *crlEnforcerLax) isCertAllowedAgainstIssuer(crt, issuer *x509.Certificate) (bool, error) {
	if len(crt.CRLDistributionPoints) == 0 {
		// Lax, no crl distribution point is allowed
		return true, nil
	}

	var lastErr error
	for _, dp := range crt.CRLDistributionPoints {
		// check presence in global store first
		if entry, ok := e.globalStore.getEntry(dp); ok {
			return !entry.snapshot().containsSerial(crt.SerialNumber), nil
		}

		if e.whitelistEnabled && !slices.Contains(e.AllowedCRLDistributionPoints, dp) {
			// Distribution Point is not in whitelist
			lastErr = fmt.Errorf("CRL URI %q is not in the allow-list", dp)
			continue
		}

		snap, err := e.snaphotProvider.getVerifiedSnapshot(e.store, dp, issuer)
		if err != nil {
			lastErr = err
			// This DP failed, using another alternative
			continue
		}

		// A valid CDP has been found, check if cert is revoked
		return !snap.containsSerial(crt.SerialNumber), nil
	}

	// No verified DP
	return false, fmt.Errorf("all CRL distribution points failed: %w", lastErr)
}

//////////////////////
//
//   Strict enforcer
//
//////////////////////

type crlEnforcerStrict struct {
	whitelistEnabled             bool
	AllowedCRLDistributionPoints []string
	// local http based store
	store *CRLStore
	// global store with file based CRLs
	globalStore     *CRLStore
	snaphotProvider crlSnaphotProvider
}

// Unexpired certificates according to CRL definitions are allowed
// CRL attributes are mandatory on certificates
func (e *crlEnforcerStrict) IsChainAllowed(chain []*x509.Certificate) (bool, error) {
	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		issuer := chain[i+1] // emitter, validated by TLS handshake

		allowed, err := e.isCertAllowedAgainstIssuer(cert, issuer)
		if err != nil {
			return false, fmt.Errorf("checking cert CN=%q: %w", cert.Subject.CommonName, err)
		}
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}

// Check wether a single certificate is allowed
func (e *crlEnforcerStrict) isCertAllowedAgainstIssuer(crt, issuer *x509.Certificate) (bool, error) {
	var lastErr error
	for _, dp := range crt.CRLDistributionPoints {
		// check presence in global store first
		if entry, ok := e.globalStore.getEntry(dp); ok {
			return !entry.snapshot().containsSerial(crt.SerialNumber), nil
		}

		if e.whitelistEnabled && !slices.Contains(e.AllowedCRLDistributionPoints, dp) {
			// Distribution Point is not in whitelist
			lastErr = fmt.Errorf("CRL URI %q is not in the allow-list", dp)
			continue
		}

		snap, err := e.snaphotProvider.getVerifiedSnapshot(e.store, dp, issuer)
		if err != nil {
			lastErr = err
			// This DP failed, using another alternative
			continue
		}

		// A valid CDP has been found, check if cert is revoked
		return !snap.containsSerial(crt.SerialNumber), nil
	}

	// No verified DP
	return false, fmt.Errorf("all CRL distribution points failed: %w", lastErr)
}
