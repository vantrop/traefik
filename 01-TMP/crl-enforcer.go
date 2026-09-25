package crlenforcer

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Config holds the plugin configuration.
type Config struct {
	// AllowedCRLURIs is the list of CRL distribution point URIs that are
	// trusted. Any certificate referencing a URI outside this list is rejected.
	AllowedCRLURIs []string `json:"allowedCRLURIs,omitempty"`

	// RefreshInterval controls how often a cached CRL is considered stale and
	// must be re-fetched. Defaults to 24 * 7 hour (1 week).
	RefreshInterval time.Duration `json:"refreshInterval,omitempty"`

	// HTTPTimeout is the timeout used when fetching a remote CRL. Defaults to
	// 10 seconds.
	HTTPTimeout time.Duration `json:"httpTimeout,omitempty"`
}

// CreateConfig returns a Config with sensible defaults.
func CreateConfig() *Config {
	return &Config{
		RefreshInterval: time.Hour * 24 * 7,
		HTTPTimeout:     10 * time.Second,
		AllowedCRLURIs:  []string{},
	}
}

// ---------------------------------------------------------------------------
// CRL distribution point cache entry
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CRL Distribution Point – entrée du cache avec verrou propre
// ---------------------------------------------------------------------------

// crlSnapshot est une structure immuable représentant un état du CRL à un
// instant donné. Elle est remplacée atomiquement lors d'un refresh, ce qui
// permet aux lecteurs de continuer à utiliser l'ancienne version sans verrou.
type crlSnapshot struct {
	crl            *x509.RevocationList
	revokedSerials map[string]struct{}
	modTime        time.Time
}

func (s *crlSnapshot) containsSerial(serial *big.Int) bool {
	_, revoked := s.revokedSerials[serial.String()]
	return revoked
}

func (s *crlSnapshot) needsRefresh(interval time.Duration) bool {
	if time.Since(s.modTime) > interval {
		return true
	}
	if s.crl != nil && !s.crl.NextUpdate.IsZero() && time.Now().After(s.crl.NextUpdate) {
		return true
	}
	return false
}

// crlEntry encapsule le snapshot courant et un mutex dédié au refresh.
// Le snapshot est accédé via un pointeur atomique pour des lectures lock-free.
type crlEntry struct {
	// snapshotPtr est un *crlSnapshot stocké atomiquement.
	// Les lecteurs font un atomic.LoadPointer, sans jamais prendre de verrou.
	snapshotPtr atomic.Pointer[crlSnapshot]

	// refreshMu garantit qu'un seul goroutine rafraîchit cette entrée à la fois.
	// Il n'est jamais tenu pendant la vérification du certificat.
	refreshMu sync.Mutex
}

// snapshot retourne le snapshot courant de manière lock-free.
func (e *crlEntry) snapshot() *crlSnapshot {
	return e.snapshotPtr.Load()
}

// storeSnapshot remplace atomiquement le snapshot courant.
func (e *crlEntry) storeSnapshot(s *crlSnapshot) {
	e.snapshotPtr.Store(s)
}

type CrlEnforcer struct {
	next   http.Handler
	name   string
	config Config

	crls CrlManager
}

// New creates a new CrlEnforcer middleware instance.
// It must be used with Traefik's clientAuth enabled so that
// r.TLS.PeerCertificates is populated.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("crlenforcer %s: config must not be nil", name)
	}

	if config.RefreshInterval == 0 {
		config.RefreshInterval = time.Hour * 24 * 7
	}

	if config.HTTPTimeout == 0 {
		config.HTTPTimeout = 10 * time.Second
	}

	var manager CrlManager
	manager = NewFailedCloseSnapManager(config)

	return &CrlEnforcer{
		next:   next,
		name:   name,
		config: *config,
		crls:   manager,
	}, nil
}

// ---------------------------------------------------------------------------
// ServeHTTP – main request handler
// ---------------------------------------------------------------------------

// ServeHTTP enforces CRL checks on every incoming request.
//
// Processing order:
//  1. Reject requests that carry no TLS client certificate.
//  2. For each peer certificate, verify it has not been revoked.
//  3. Forward the request to the next handler only when all checks pass.
func (e *CrlEnforcer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "TLS client certificate is required.", http.StatusUnauthorized)
		return
	}

	// Garde-fou explicite : si VerifiedChains est vide, soit aucun certificat
	// n'a été présenté, soit ClientAuth n'est pas configuré en mode
	// RequireAndVerifyClientCert. Dans les deux cas, on refuse.
	if len(r.TLS.VerifiedChains) == 0 {
		log.Printf("[crlenforcer] %s: No verified TLS client certificate chain found. Ensure Traefik's clientAuth is set to RequireAndVerifyClientCert.",
			e.name)
		http.Error(w, "No verified TLS client certificate chain found.",
			http.StatusUnauthorized)
		return
	}

	// Généralement une seule chaîne, mais on vérifie toutes celles proposées.
	for _, chain := range r.TLS.VerifiedChains {
		allowed, err := e.IsChainAllowed(chain)
		if err != nil {
			switch {
			case errors.Is(err, ErrNoCRLDistributionPoint):
				// Rejet explicite : le certificat ne respecte pas la
				// politique de sécurité (CDP obligatoire).
				log.Printf("[crlenforcer] %s: certificate rejected, no CRL distribution point: %v", e.name, err)
				http.Error(w, "TLS client certificate does not declare a CRL distribution point.", http.StatusUnauthorized)
				return

			case errors.Is(err, ErrCRLUnavailable):
				// Fail-closed : impossible de vérifier la révocation de
				// manière fiable, on rejette par prudence.
				log.Printf("[crlenforcer] %s: CRL unavailable, rejecting fail-closed: %v", e.name, err)
				http.Error(w, "Unable to verify certificate revocation status.", http.StatusBadGateway)
				return

			default:
				log.Printf("[crlenforcer] %s: unexpected verification error: %v", e.name, err)
				http.Error(w, "Could not verify TLS client certificate.", http.StatusBadGateway)
				return
			}
		}

		if !allowed {
			http.Error(w, "TLS client certificate chain contains a revoked certificate.", http.StatusUnauthorized)
			return
		}
	}

	// Le leaf est toujours chain[0] pour la construction du header.
	leaf := r.TLS.VerifiedChains[0][0]
	userCert, err := encodeCertHeader(leaf)
	if err != nil {
		log.Printf("[crlenforcer] %s: certificate CN=%q serial=%s could not encode certificate in header format", e.name, leaf.Subject.CommonName, leaf.SerialNumber)
	}

	// Injection dans le header (remplace passTLSClientCert)
	// On écrase toute valeur précédente pour éviter le header spoofing.
	r.Header.Del(headerTLSClientCert)
	r.Header.Set(headerTLSClientCert, userCert)

	e.next.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// CRL verification logic
// ---------------------------------------------------------------------------

// IsChainAllowed vérifie l'ensemble d'une chaîne déjà validée par TLS
// (r.TLS.VerifiedChains) contre les CRL correspondantes.
//
// chain[0] est le certificat feuille, chain[len-1] est généralement la racine
// (self-signed). La racine est exclue de la vérification CRL car les CA
// racines ne sont typiquement pas révoquées via CRL mais retirées du trust
// store.
func (e *CrlEnforcer) IsChainAllowed(chain []*x509.Certificate) (bool, error) {
	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		issuer := chain[i+1] // émetteur direct, déjà validé par le TLS handshake

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

// isCertAllowedAgainstIssuer vérifie un certificat contre les CRL déclarées,
// en essayant les distribution points dans l'ordre jusqu'à ce qu'un
// téléchargement + vérification réussisse (mirrors).
func (e *CrlEnforcer) isCertAllowedAgainstIssuer(crt, issuer *x509.Certificate) (bool, error) {
	if len(crt.CRLDistributionPoints) == 0 {
		// Politique fail-closed : un certificat sans CDP configuré est rejeté.
		// (à adapter selon votre politique de sécurité)
		return false, ErrNoCRLDistributionPoint
	}

	var lastErr error

	for _, uri := range crt.CRLDistributionPoints {
		if !slices.Contains(e.config.AllowedCRLURIs, uri) {
			// URI non autorisée : on ne l'essaie même pas, on continue vers
			// la suivante (elle peut être un mirror valide).
			lastErr = fmt.Errorf("CRL URI %q is not in the allow-list", uri)
			continue
		}

		snap, err := e.crls.getVerifiedSnapshot(uri, issuer)
		if err != nil {
			// Ce mirror a échoué (réseau, signature invalide, etc.) :
			// on essaie le suivant plutôt que de rejeter immédiatement.
			lastErr = fmt.Errorf("CRL %q: %w", uri, err)
			continue
		}

		// Un CDP valide et vérifié a été trouvé : on statue dessus.
		return !snap.containsSerial(crt.SerialNumber), nil
	}

	// Aucun distribution point n'a pu être vérifié avec succès.
	return false, fmt.Errorf("all CRL distribution points failed: %w", lastErr)
}
