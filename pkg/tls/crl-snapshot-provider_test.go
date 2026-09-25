package tls

import (
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenSnapshotProvider_NewEntry_Success(t *testing.T) {
	ca := newTestCA(t)
	der := newTestCRLDER(t, ca, 1, nil, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	srv := newHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(der) })

	store := &CRLStore{crlReloadInterval: time.Hour}
	provider := &openSnaphotProvider{clientHolder: newCRLHTTPClientHolder(http.DefaultTransport.(*http.Transport).Clone(), time.Second)}

	snap, err := provider.getVerifiedSnapshot(store, srv.URL, ca.cert)
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(1), snap.crlSerial())
}

func TestOpenSnapshotProvider_NewEntry_LoadFailure(t *testing.T) {
	srv := newHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	ca := newTestCA(t)
	store := &CRLStore{crlReloadInterval: time.Hour}
	provider := &openSnaphotProvider{clientHolder: newCRLHTTPClientHolder(http.DefaultTransport.(*http.Transport).Clone(), time.Second)}

	_, err := provider.getVerifiedSnapshot(store, srv.URL, ca.cert)
	assert.Error(t, err)
}

func TestOpenSnapshotProvider_FreshSnapshot_NoReload(t *testing.T) {
	ca := newTestCA(t)
	store := &CRLStore{crlReloadInterval: time.Hour}
	provider := &openSnaphotProvider{clientHolder: newCRLHTTPClientHolder(http.DefaultTransport.(*http.Transport).Clone(), time.Second)}

	entry := store.getOrCreateEntry("dp1")
	fresh := &dynamicCrlSnapshot{crlSnapshotCommon{
		number: big.NewInt(42), modTime: time.Now(), nextUpdate: time.Now().Add(time.Hour),
	}}
	entry.storeSnapshot(fresh)
	entry.loader = loaderFunc(func(e *crlEntry) (crlSnapshot, error) {
		t.Fatal("reload should not be triggered for a fresh snapshot")
		return nil, nil
	})

	snap, err := provider.getVerifiedSnapshot(store, "dp1", ca.cert)
	require.NoError(t, err)
	assert.Same(t, crlSnapshot(fresh), snap)
}

func TestOpenSnapshotProvider_StaleSnapshot_Refreshes(t *testing.T) {
	ca := newTestCA(t)
	der := newTestCRLDER(t, ca, 2, nil, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	srv := newHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(der) })

	store := &CRLStore{crlReloadInterval: time.Millisecond}
	provider := &openSnaphotProvider{clientHolder: newCRLHTTPClientHolder(http.DefaultTransport.(*http.Transport).Clone(), time.Second)}

	entry := store.getOrCreateEntry(srv.URL)
	entry.loader = &crlHTTPLoader{
		distributionPoint: srv.URL,
		clientHolder:      provider.clientHolder,
		issuer:            ca.cert,
	}
	entry.storeSnapshot(&dynamicCrlSnapshot{crlSnapshotCommon{
		number: big.NewInt(1), modTime: time.Now().Add(-time.Hour), nextUpdate: time.Now().Add(time.Hour),
	}})

	snap, err := provider.getVerifiedSnapshot(store, srv.URL, ca.cert)
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(2), snap.crlSerial())
}

func TestOpenSnapshotProvider_ConcurrentRefresh_ReturnsStale(t *testing.T) {
	ca := newTestCA(t)
	store := &CRLStore{crlReloadInterval: time.Millisecond}
	provider := &openSnaphotProvider{clientHolder: newCRLHTTPClientHolder(http.DefaultTransport.(*http.Transport).Clone(), time.Second)}

	entry := store.getOrCreateEntry("dp1")
	stale := &dynamicCrlSnapshot{crlSnapshotCommon{
		number: big.NewInt(1), modTime: time.Now().Add(-time.Hour), nextUpdate: time.Now().Add(time.Hour),
	}}
	entry.storeSnapshot(stale)

	// Simulate an in-flight refresh held by another goroutine.
	entry.refreshMu.Lock()
	defer entry.refreshMu.Unlock()

	snap, err := provider.getVerifiedSnapshot(store, "dp1", ca.cert)
	require.NoError(t, err)
	assert.Same(t, crlSnapshot(stale), snap)
}

func TestFailedCloseProvider_FreshSnapshot_FastPath(t *testing.T) {
	ca := newTestCA(t)
	store := &CRLStore{crlReloadInterval: time.Hour}
	provider := &failedCloseSnapshotProvider{clientHolder: newCRLHTTPClientHolder(http.DefaultTransport.(*http.Transport).Clone(), time.Second)}

	entry := store.getOrCreateEntry("dp1")
	fresh := &dynamicCrlSnapshot{crlSnapshotCommon{
		number: big.NewInt(1), modTime: time.Now(), nextUpdate: time.Now().Add(time.Hour),
	}}
	entry.storeSnapshot(fresh)
	entry.loader = loaderFunc(func(e *crlEntry) (crlSnapshot, error) {
		t.Fatal("reload should not be triggered for a fresh snapshot")
		return nil, nil
	})

	snap, err := provider.getVerifiedSnapshot(store, "dp1", ca.cert)
	require.NoError(t, err)
	assert.Same(t, crlSnapshot(fresh), snap)
}

func TestFailedCloseProvider_StaleSnapshot_BlockingRefreshSuccess(t *testing.T) {
	ca := newTestCA(t)
	der := newTestCRLDER(t, ca, 2, nil, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	srv := newHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(der) })

	store := &CRLStore{crlReloadInterval: time.Millisecond}
	provider := &failedCloseSnapshotProvider{clientHolder: newCRLHTTPClientHolder(http.DefaultTransport.(*http.Transport).Clone(), time.Second)}

	entry := store.getOrCreateEntry(srv.URL)
	entry.loader = &crlHTTPLoader{
		distributionPoint: srv.URL,
		clientHolder:      provider.clientHolder,
		issuer:            ca.cert,
	}
	entry.storeSnapshot(&dynamicCrlSnapshot{crlSnapshotCommon{
		number: big.NewInt(1), modTime: time.Now().Add(-time.Hour), nextUpdate: time.Now().Add(time.Hour),
	}})

	snap, err := provider.getVerifiedSnapshot(store, srv.URL, ca.cert)
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(2), snap.crlSerial())
}

func TestFailedCloseProvider_RefreshFailure_FailsClosedEvenWithStaleSnapshot(t *testing.T) {
	ca := newTestCA(t)
	srv := newHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	store := &CRLStore{crlReloadInterval: time.Millisecond}
	provider := &failedCloseSnapshotProvider{clientHolder: newCRLHTTPClientHolder(http.DefaultTransport.(*http.Transport).Clone(), time.Second)}

	entry := store.getOrCreateEntry(srv.URL)
	entry.loader = &crlHTTPLoader{
		distributionPoint: srv.URL,
		clientHolder:      provider.clientHolder,
		issuer:            ca.cert,
	}
	entry.storeSnapshot(&dynamicCrlSnapshot{crlSnapshotCommon{
		number: big.NewInt(1), modTime: time.Now().Add(-time.Hour), nextUpdate: time.Now().Add(time.Hour),
	}})

	_, err := provider.getVerifiedSnapshot(store, srv.URL, ca.cert)
	assert.Error(t, err) // fail-closed: stale data must never be returned silently
}

func TestFailedCloseProvider_NoSnapshot_LoadFailure(t *testing.T) {
	ca := newTestCA(t)
	srv := newHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	store := &CRLStore{crlReloadInterval: time.Hour}
	provider := &failedCloseSnapshotProvider{clientHolder: newCRLHTTPClientHolder(http.DefaultTransport.(*http.Transport).Clone(), time.Second)}

	_, err := provider.getVerifiedSnapshot(store, srv.URL, ca.cert)
	assert.Error(t, err)
}
