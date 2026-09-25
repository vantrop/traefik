package crlenforcer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.tech.orange/gward/crlenforcer"
)

// ---------------------------------------------------------------------------
// Serveur CRL dynamique
// ---------------------------------------------------------------------------

// dynamicCRLServer expose un endpoint HTTP dont le contenu peut être modifié
// à chaud, ce qui permet de simuler un refresh, un rollback, ou une CRL
// forgée sans redémarrer le serveur de test.
type dynamicCRLServer struct {
	mu   sync.Mutex
	der  []byte
	down bool
}

func (s *dynamicCRLServer) set(der []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.der = der
}

// setDown simule la panne (ou le rétablissement) du serveur CRL.
func (s *dynamicCRLServer) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

func (s *dynamicCRLServer) snapshot() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.der, s.down
}

// newDynamicCRLServer démarre un serveur de test servant le contenu courant
// de dynamicCRLServer sur GET /crl.
func newDynamicCRLServer(t *testing.T) (*dynamicCRLServer, string) {
	t.Helper()
	ds := &dynamicCRLServer{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		der, down := ds.snapshot()
		if down || der == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(der)
	}))
	t.Cleanup(srv.Close)

	return ds, srv.URL + "/crl"
}

// newFailingServer retourne systématiquement 500, pour simuler un miroir CRL
// hors service.
func newFailingServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/crl"
}

// ---------------------------------------------------------------------------
// Construction de la PKI
// ---------------------------------------------------------------------------

// testPKI modélise une chaîne à trois niveaux :
//
//	Root CA ──(CRL @ rootCRLURL)──► Intermediate CA ──(CRL @ interCRLURL)──► Leaf
//
// La racine n'a volontairement aucun CRLDistributionPoint : conformément à la
// politique PKIX standard, une CA racine n'est pas vérifiée via CRL mais
// retirée du trust store en cas de compromission.
type testPKI struct {
	rootKey  *ecdsa.PrivateKey
	rootCert *x509.Certificate

	interKey  *ecdsa.PrivateKey
	interCert *x509.Certificate

	leafKey  *ecdsa.PrivateKey
	leafCert *x509.Certificate

	revokedLeafKey  *ecdsa.PrivateKey
	revokedLeafCert *x509.Certificate

	rootCRLURL  string
	interCRLURL string
}

func newRootCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := mustGenerateKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	raw := mustSignCert(t, template, template, &key.PublicKey, key)
	return key, mustParseCert(t, raw)
}

// newIntermediateCA construit la CA intermédiaire avec son CRLDistributionPoint
// pointant vers la CRL de la racine.
func newIntermediateCA(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, rootCRLURL string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := mustGenerateKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{rootCRLURL},
	}
	raw := mustSignCert(t, template, root, &key.PublicKey, rootKey)
	return key, mustParseCert(t, raw)
}

// newLeafCert construit un certificat feuille avec un serial et des
// CRLDistributionPoints personnalisables (utile pour le cas "aucun CDP" ou
// "plusieurs miroirs").
func newLeafCert(
	t *testing.T,
	cn string,
	serial int64,
	inter *x509.Certificate,
	interKey *ecdsa.PrivateKey,
	cdps []string,
) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := mustGenerateKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CRLDistributionPoints: cdps,
	}
	raw := mustSignCert(t, template, inter, &key.PublicKey, interKey)
	return key, mustParseCert(t, raw)
}

// newFullPKI construit une PKI complète prête à l'emploi, avec :
//   - une CRL racine vide (l'intermédiaire n'est pas révoqué)
//   - une CRL intermédiaire révoquant revokedLeafCert
//
// Les deux CRL sont servies par des dynamicCRLServer, permettant aux tests
// de muter leur contenu à la volée si nécessaire.
func newFullPKI(t *testing.T) (*testPKI, *dynamicCRLServer, *dynamicCRLServer) {
	t.Helper()

	rootSrv, rootCRLURL := newDynamicCRLServer(t)
	interSrv, interCRLURL := newDynamicCRLServer(t)

	rootKey, rootCert := newRootCA(t)
	interKey, interCert := newIntermediateCA(t, rootCert, rootKey, rootCRLURL)

	leafKey, leafCert := newLeafCert(t, "valid-user", 10, interCert, interKey, []string{interCRLURL})
	revokedLeafKey, revokedLeafCert := newLeafCert(t, "revoked-user", 11, interCert, interKey, []string{interCRLURL})

	pki := &testPKI{
		rootKey:         rootKey,
		rootCert:        rootCert,
		interKey:        interKey,
		interCert:       interCert,
		leafKey:         leafKey,
		leafCert:        leafCert,
		revokedLeafKey:  revokedLeafKey,
		revokedLeafCert: revokedLeafCert,
		rootCRLURL:      rootCRLURL,
		interCRLURL:     interCRLURL,
	}

	// CRL racine : vide par défaut (intermédiaire non révoqué)
	rootSrv.set(mustBuildCRL(t, rootCert, rootKey, nil, defaultCRLOpts()))

	// CRL intermédiaire : révoque le leaf "revoked-user"
	interSrv.set(mustBuildCRL(t, interCert, interKey, []*big.Int{big.NewInt(11)}, defaultCRLOpts()))

	return pki, rootSrv, interSrv
}

// ---------------------------------------------------------------------------
// Construction des CRL
// ---------------------------------------------------------------------------

// crlOpts permet de personnaliser les champs temporels et le numéro de
// séquence d'une CRL de test.
type crlOpts struct {
	number     *big.Int
	thisUpdate time.Time
	nextUpdate time.Time
}

func defaultCRLOpts() crlOpts {
	return crlOpts{
		number:     big.NewInt(1),
		thisUpdate: time.Now().Add(-time.Minute),
		nextUpdate: time.Now().Add(24 * time.Hour),
	}
}

// mustBuildCRL construit et signe une CRL DER.
//
// Le paramètre issuerKey est la clé utilisée pour SIGNER la CRL ; le
// paramètre issuerCert détermine le champ "Issuer" inscrit dans la CRL.
// Passer volontairement une issuerKey qui ne correspond pas à issuerCert
// permet de simuler une CRL forgée dans les tests de sécurité.
func mustBuildCRL(
	t *testing.T,
	issuerCert *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	revokedSerials []*big.Int,
	opts crlOpts,
) []byte {
	t.Helper()

	entries := make([]x509.RevocationListEntry, len(revokedSerials))
	for i, s := range revokedSerials {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   s,
			RevocationTime: time.Now().Add(-time.Minute),
		}
	}

	template := &x509.RevocationList{
		Number:                    opts.number,
		ThisUpdate:                opts.thisUpdate,
		NextUpdate:                opts.nextUpdate,
		RevokedCertificateEntries: entries,
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, issuerCert, issuerKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return der
}

// ---------------------------------------------------------------------------
// Helpers PKI génériques
// ---------------------------------------------------------------------------

func mustGenerateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func mustSignCert(t *testing.T, template, parent *x509.Certificate, pub *ecdsa.PublicKey, signerKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signerKey)
	if err != nil {
		t.Fatalf("create certificate %q: %v", template.Subject.CommonName, err)
	}
	return raw
}

func mustParseCert(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	crt, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return crt
}

// ---------------------------------------------------------------------------
// Helpers requête / middleware
// ---------------------------------------------------------------------------

// newRequestWithVerifiedChain construit une requête simulant une chaîne déjà
// validée cryptographiquement par le handshake TLS (r.TLS.VerifiedChains).
// chain[0] doit être le certificat feuille, chain[len-1] la racine.
func newRequestWithVerifiedChain(chain ...*x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{chain},
	}
	return r
}

// capturingHandler retourne un handler qui stocke la dernière requête reçue.
func capturingHandler(captured **http.Request) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*captured = r
		w.WriteHeader(http.StatusOK)
	})
}

// newMiddleware construit le middleware avec une configuration personnalisable.
func newMiddleware(t *testing.T, allowedURIs []string, next http.Handler, mutate func(*crlenforcer.Config)) http.Handler {
	t.Helper()

	cfg := crlenforcer.CreateConfig()
	cfg.AllowedCRLURIs = allowedURIs
	cfg.RefreshInterval = time.Hour
	cfg.HTTPTimeout = 5 * time.Second

	if mutate != nil {
		mutate(cfg)
	}

	handler, err := crlenforcer.New(t.Context(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return handler
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// ---------------------------------------------------------------------------
// Tests : cas nominaux
// ---------------------------------------------------------------------------

// TestNoTLS vérifie qu'une requête sans TLS est rejetée avec 401.
func TestNoTLS(t *testing.T) {
	pki, _, _ := newFullPKI(t)
	handler := newMiddleware(t, []string{pki.rootCRLURL, pki.interCRLURL}, okHandler(), nil)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusUnauthorized)
}

// TestNoVerifiedChains vérifie qu'une connexion TLS sans chaîne vérifiée
// (VerifiedChains vide) est rejetée. Ce cas se produit notamment si Traefik
// n'est pas configuré en RequireAndVerifyClientCert.
func TestNoVerifiedChains(t *testing.T) {
	pki, _, _ := newFullPKI(t)
	handler := newMiddleware(t, []string{pki.rootCRLURL, pki.interCRLURL}, okHandler(), nil)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{} // VerifiedChains vide
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusUnauthorized)
}

// TestValidChain vérifie qu'une chaîne complète (leaf + intermédiaire + racine),
// aucun maillon révoqué, est acceptée et que le header ne contient QUE le leaf.
func TestValidChain(t *testing.T) {
	pki, _, _ := newFullPKI(t)

	var capturedReq *http.Request
	handler := newMiddleware(t,
		[]string{pki.rootCRLURL, pki.interCRLURL},
		capturingHandler(&capturedReq),
		nil,
	)

	r := newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusOK)

	if capturedReq == nil {
		t.Fatal("next handler was not called")
	}

	values := capturedReq.Header.Values("X-Forwarded-Tls-Client-Cert")
	if len(values) != 1 {
		t.Fatalf("expected exactly 1 cert in header, got %d", len(values))
	}
	if strings.Contains(values[0], "-----") {
		t.Error("header should not contain PEM markers")
	}
}

// TestRevokedLeaf vérifie qu'un certificat feuille révoqué est rejeté,
// même si la chaîne de CA est parfaitement valide.
func TestRevokedLeaf(t *testing.T) {
	pki, _, _ := newFullPKI(t)
	handler := newMiddleware(t, []string{pki.rootCRLURL, pki.interCRLURL}, okHandler(), nil)

	r := newRequestWithVerifiedChain(pki.revokedLeafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusUnauthorized)
}

// ---------------------------------------------------------------------------
// Tests : validation de toute la chaîne
// ---------------------------------------------------------------------------

// TestRevokedIntermediate vérifie qu'une CA intermédiaire révoquée par la CRL
// de la racine entraîne le rejet, même si le certificat feuille lui-même
// n'est pas révoqué.
func TestRevokedIntermediate(t *testing.T) {
	pki, rootSrv, _ := newFullPKI(t)

	// La racine révoque désormais l'intermédiaire (serial 2).
	rootSrv.set(mustBuildCRL(t, pki.rootCert, pki.rootKey, []*big.Int{big.NewInt(2)}, defaultCRLOpts()))

	handler := newMiddleware(t, []string{pki.rootCRLURL, pki.interCRLURL}, okHandler(), nil)

	// Le leaf lui-même est parfaitement valide.
	r := newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusUnauthorized)
}

// ---------------------------------------------------------------------------
// Tests : sécurité cryptographique de la CRL
// ---------------------------------------------------------------------------

// TestForgedCRLSignatureRejected vérifie qu'une CRL signée par une clé qui ne
// correspond pas au certificat émetteur est rejetée, simulant un attaquant
// MITM contrôlant le endpoint CRL (typiquement en HTTP non chiffré).
func TestForgedCRLSignatureRejected(t *testing.T) {
	pki, _, interSrv := newFullPKI(t)

	// La CRL prétend être émise par l'intermédiaire (champ Issuer correct)
	// mais est en réalité signée avec la clé de la racine : signature invalide.
	forged := mustBuildCRL(t, pki.interCert, pki.rootKey, nil, defaultCRLOpts())
	interSrv.set(forged)

	handler := newMiddleware(t, []string{pki.rootCRLURL, pki.interCRLURL}, okHandler(), nil)

	r := newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	// Premier chargement en échec de vérification cryptographique → 502.
	assertStatus(t, w, http.StatusBadGateway)
}

// TestExpiredCRLRejected vérifie qu'une CRL dont le NextUpdate est déjà
// dépassé est rejetée lors du premier chargement.
func TestExpiredCRLRejected(t *testing.T) {
	pki, _, interSrv := newFullPKI(t)

	expiredOpts := crlOpts{
		number:     big.NewInt(1),
		thisUpdate: time.Now().Add(-48 * time.Hour),
		nextUpdate: time.Now().Add(-24 * time.Hour), // déjà expirée
	}
	interSrv.set(mustBuildCRL(t, pki.interCert, pki.interKey, nil, expiredOpts))

	handler := newMiddleware(t, []string{pki.rootCRLURL, pki.interCRLURL}, okHandler(), nil)

	r := newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusBadGateway)
}

// TestFutureCRLRejected vérifie qu'une CRL dont le ThisUpdate est dans le
// futur (horloge désynchronisée ou tentative de contournement) est rejetée.
func TestFutureCRLRejected(t *testing.T) {
	pki, _, interSrv := newFullPKI(t)

	futureOpts := crlOpts{
		number:     big.NewInt(1),
		thisUpdate: time.Now().Add(24 * time.Hour), // dans le futur
		nextUpdate: time.Now().Add(48 * time.Hour),
	}
	interSrv.set(mustBuildCRL(t, pki.interCert, pki.interKey, nil, futureOpts))

	handler := newMiddleware(t, []string{pki.rootCRLURL, pki.interCRLURL}, okHandler(), nil)

	r := newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusBadGateway)
}

// TestCRLRollbackProtection vérifie qu'une tentative de rollback (CRLNumber
// régressif) ne permet JAMAIS de contourner une révocation, que ce soit en
// conservant l'ancien état (comportement historique) ou en rejetant
// explicitement la requête (comportement fail-closed actuel).
func TestCRLRollbackProtection(t *testing.T) {
	pki, _, interSrv := newFullPKI(t)

	handler := newMiddleware(t,
		[]string{pki.rootCRLURL, pki.interCRLURL},
		okHandler(),
		func(c *crlenforcer.Config) { c.RefreshInterval = 100 * time.Millisecond },
	)

	// CRL n°2 : révoque le leaf "revoked-user".
	interSrv.set(mustBuildCRL(t, pki.interCert, pki.interKey,
		[]*big.Int{big.NewInt(11)},
		crlOpts{number: big.NewInt(2), thisUpdate: time.Now().Add(-time.Minute), nextUpdate: time.Now().Add(24 * time.Hour)},
	))

	r := newRequestWithVerifiedChain(pki.revokedLeafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assertStatus(t, w, http.StatusUnauthorized)

	// Tentative de rollback : CRL n°1, sans révocation.
	interSrv.set(mustBuildCRL(t, pki.interCert, pki.interKey,
		nil,
		crlOpts{number: big.NewInt(1), thisUpdate: time.Now(), nextUpdate: time.Now().Add(24 * time.Hour)},
	))

	time.Sleep(200 * time.Millisecond)

	r = newRequestWithVerifiedChain(pki.revokedLeafCert, pki.interCert, pki.rootCert)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	// La propriété de sécurité essentielle : le rollback ne doit JAMAIS
	// permettre l'acceptation du certificat révoqué.
	if w.Code == http.StatusOK {
		t.Fatal("SECURITY: CRL rollback attack succeeded, revoked certificate was accepted")
	}
	// Avec la politique fail-closed, le refresh échoue à la vérification
	// anti-rollback → rejet technique (502).
	assertStatus(t, w, http.StatusBadGateway)
}

// ---------------------------------------------------------------------------
// Tests : politique fail-closed
// ---------------------------------------------------------------------------

// TestNoCRLDistributionPointsFailsClosed vérifie qu'un certificat sans aucun
// CRLDistributionPoint est rejeté plutôt qu'implicitement accepté.
//
// Note : avec l'implémentation actuelle, ce cas remonte une erreur et produit
// un 502 (chemin d'erreur générique), et non un 401 dédié. Ce comportement
// pourrait être affiné selon la politique de sécurité souhaitée, mais ce
// test documente le comportement réel du code.
func TestNoCRLDistributionPointsFailsClosed(t *testing.T) {
	pki, _, _ := newFullPKI(t)

	// Certificat feuille sans aucun CDP.
	_, noCDPLeaf := newLeafCert(t, "no-cdp-user", 12, pki.interCert, pki.interKey, nil)

	handler := newMiddleware(t, []string{pki.rootCRLURL, pki.interCRLURL}, okHandler(), nil)

	r := newRequestWithVerifiedChain(noCDPLeaf, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected a fail-closed rejection (502 or 401), got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "does not declare a CRL distribution point") {
		t.Errorf("expected explicit CDP-missing message, got: %q", body)
	}
}

// TestStaleCRLWithUnreachableEndpointRejected vérifie que si le cache CRL
// devient périmé (selon RefreshInterval) et que l'endpoint de distribution
// devient injoignable, la requête est rejetée. Le middleware ne doit JAMAIS
// statuer sur la base d'un CRL périmé.
//
// Note d'implémentation : on utilise volontairement un NextUpdate de CRL
// largement dans le futur (24h) et on contrôle la staleness via
// RefreshInterval uniquement. Cela évite toute dépendance au temps réel de
// génération de la PKI (key generation, signatures), qui peut varier de
// quelques millisecondes à plusieurs centaines de millisecondes selon la
// machine, rendant un timing basé sur NextUpdate intrinsèquement fragile.
func TestStaleCRLWithUnreachableEndpointRejected(t *testing.T) {
	pki, _, interSrv := newFullPKI(t)

	// CRL valide avec une fenêtre de validité large : NextUpdate ne doit
	// jamais être la cause du déclenchement du refresh dans ce test.
	interSrv.set(mustBuildCRL(t, pki.interCert, pki.interKey, nil, crlOpts{
		number:     big.NewInt(1),
		thisUpdate: time.Now().Add(-time.Minute),
		nextUpdate: time.Now().Add(24 * time.Hour),
	}))

	const refreshInterval = 200 * time.Millisecond

	handler := newMiddleware(t,
		[]string{pki.rootCRLURL, pki.interCRLURL},
		okHandler(),
		func(c *crlenforcer.Config) {
			c.RefreshInterval = refreshInterval
			c.HTTPTimeout = 500 * time.Millisecond
		},
	)

	// ── Étape 1 : premier chargement, endpoint disponible → 200 ────────────
	r := newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assertStatus(t, w, http.StatusOK)

	// ── Étape 2 : on attend explicitement l'expiration du cache local ──────
	// On ajoute une marge de sécurité (×2) pour absorber la jitter du
	// scheduler de test, tout en restant indépendant du temps de génération
	// de la PKI (qui a eu lieu AVANT le début du chrono de ce test).
	time.Sleep(2 * refreshInterval)

	// ── Étape 3 : l'endpoint CRL tombe en panne ─────────────────────────────
	interSrv.setDown(true)

	// ── Étape 4 : la requête DOIT être rejetée ──────────────────────────────
	r = newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code == http.StatusOK {
		t.Fatal("SECURITY: request was accepted using a stale, unrefreshable CRL cache")
	}
	assertStatus(t, w, http.StatusBadGateway)
}

// TestStaleCRLRecoversWhenEndpointComesBackUp complète le test précédent en
// vérifiant que le service se rétablit normalement une fois l'endpoint de
// nouveau disponible.
func TestStaleCRLRecoversWhenEndpointComesBackUp(t *testing.T) {
	pki, _, interSrv := newFullPKI(t)

	interSrv.set(mustBuildCRL(t, pki.interCert, pki.interKey, nil, crlOpts{
		number:     big.NewInt(1),
		thisUpdate: time.Now().Add(-time.Minute),
		nextUpdate: time.Now().Add(24 * time.Hour),
	}))

	const refreshInterval = 200 * time.Millisecond

	handler := newMiddleware(t,
		[]string{pki.rootCRLURL, pki.interCRLURL},
		okHandler(),
		func(c *crlenforcer.Config) {
			c.RefreshInterval = refreshInterval
			c.HTTPTimeout = 500 * time.Millisecond
		},
	)

	// ── Étape 1 : chargement initial, endpoint disponible → 200 ────────────
	r := newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assertStatus(t, w, http.StatusOK)

	// ── Étape 2 : expiration du cache local ─────────────────────────────────
	time.Sleep(2 * refreshInterval)

	// ── Étape 3 : panne de l'endpoint → rejet attendu ───────────────────────
	interSrv.setDown(true)
	r = newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assertStatus(t, w, http.StatusBadGateway)

	// ── Étape 4 : rétablissement, nouvelle CRL publiée ──────────────────────
	interSrv.set(mustBuildCRL(t, pki.interCert, pki.interKey, nil, crlOpts{
		number:     big.NewInt(2), // strictement croissant : pas de rollback
		thisUpdate: time.Now(),
		nextUpdate: time.Now().Add(24 * time.Hour),
	}))
	interSrv.setDown(false)

	// ── Étape 5 : le service doit se rétablir → 200 ─────────────────────────
	r = newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Tests : allow-list et disponibilité
// ---------------------------------------------------------------------------

// TestUntrustedCRLURI vérifie qu'un certificat référençant une CRL URI
// absente de l'allow-list est rejeté.
func TestUntrustedCRLURI(t *testing.T) {
	pki, _, _ := newFullPKI(t)

	// L'allow-list ne contient PAS l'URI réelle du CRL intermédiaire.
	handler := newMiddleware(t,
		[]string{pki.rootCRLURL, "http://untrusted.example.com/crl"},
		okHandler(),
		nil,
	)

	r := newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusBadGateway) // toutes les URI ont échoué (aucune de confiance)
}

// TestCRLServerUnavailable vérifie que si l'unique CRL distribution point
// est injoignable dès le premier chargement, la requête échoue en 502.
func TestCRLServerUnavailable(t *testing.T) {
	pki, _, _ := newFullPKI(t)

	downURL := newFailingServer(t)
	_, leafWithDownCDP := newLeafCert(t, "down-cdp-user", 13, pki.interCert, pki.interKey, []string{downURL})

	handler := newMiddleware(t,
		[]string{pki.rootCRLURL, downURL},
		okHandler(),
		func(c *crlenforcer.Config) { c.HTTPTimeout = 500 * time.Millisecond },
	)

	r := newRequestWithVerifiedChain(leafWithDownCDP, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusBadGateway)
}

// TestCRLMirrorFailover vérifie que si le premier CRLDistributionPoint est
// hors service, le middleware bascule sur le second miroir et accepte le
// certificat si celui-ci est valide.
func TestCRLMirrorFailover(t *testing.T) {
	pki, _, interSrv := newFullPKI(t)

	downURL := newFailingServer(t)

	// Le leaf référence deux CDP : le premier down, le second fonctionnel.
	_, leafWithMirrors := newLeafCert(t, "mirror-user", 14, pki.interCert, pki.interKey,
		[]string{downURL, pki.interCRLURL})

	// La CRL du miroir fonctionnel ne révoque rien.
	interSrv.set(mustBuildCRL(t, pki.interCert, pki.interKey, nil, defaultCRLOpts()))

	handler := newMiddleware(t,
		[]string{pki.rootCRLURL, downURL, pki.interCRLURL},
		okHandler(),
		nil,
	)

	r := newRequestWithVerifiedChain(leafWithMirrors, pki.interCert, pki.rootCert)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Tests : anti-spoofing des headers
// ---------------------------------------------------------------------------

// TestHeaderSpoofingPrevention vérifie qu'un header X-Forwarded-Tls-Client-Cert
// injecté par le client est supprimé avant transmission au handler suivant.
func TestHeaderSpoofingPrevention(t *testing.T) {
	pki, _, _ := newFullPKI(t)

	var capturedReq *http.Request
	handler := newMiddleware(t,
		[]string{pki.rootCRLURL, pki.interCRLURL},
		capturingHandler(&capturedReq),
		nil,
	)

	r := newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
	r.Header.Set("X-Forwarded-Tls-Client-Cert", "FAKE_INJECTED_VALUE")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assertStatus(t, w, http.StatusOK)

	if capturedReq == nil {
		t.Fatal("next handler was not called")
	}
	for _, v := range capturedReq.Header.Values("X-Forwarded-Tls-Client-Cert") {
		if v == "FAKE_INJECTED_VALUE" {
			t.Error("spoofed header value was forwarded to next handler")
		}
	}
}

// ---------------------------------------------------------------------------
// Tests : concurrence
// ---------------------------------------------------------------------------

// TestConcurrentRequests vérifie la stabilité du middleware sous charge
// concurrente, en mélangeant chaînes valides et révoquées.
func TestConcurrentRequests(t *testing.T) {
	pki, _, _ := newFullPKI(t)
	handler := newMiddleware(t, []string{pki.rootCRLURL, pki.interCRLURL}, okHandler(), nil)

	const goroutines = 50
	const requestsPerGoroutine = 20

	var wg sync.WaitGroup
	errs := make(chan string, goroutines*requestsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < requestsPerGoroutine; i++ {
				var (
					r        *http.Request
					wantCode int
				)

				if id%2 == 0 {
					r = newRequestWithVerifiedChain(pki.leafCert, pki.interCert, pki.rootCert)
					wantCode = http.StatusOK
				} else {
					r = newRequestWithVerifiedChain(pki.revokedLeafCert, pki.interCert, pki.rootCert)
					wantCode = http.StatusUnauthorized
				}

				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)

				if w.Code != wantCode {
					errs <- fmt.Sprintf("goroutine %d req %d: got %d, want %d", id, i, w.Code, wantCode)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errs)

	for msg := range errs {
		t.Error(msg)
	}
}

// ---------------------------------------------------------------------------
// Assertions helpers
// ---------------------------------------------------------------------------

func assertStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Errorf("status: got %d, want %d (body: %q)", w.Code, want, w.Body.String())
	}
}
