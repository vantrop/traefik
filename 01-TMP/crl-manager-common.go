package crlenforcer

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type CommonCrlManager struct {
	entries sync.Map // crls snapshots (optimized for high read throughput)
}

// getOrCreateEntry retourne l'entrée existante ou en crée une nouvelle.
// sync.Map.LoadOrStore garantit qu'une seule entrée est créée par URI.
func (m *CommonCrlManager) getOrCreateEntry(uri string) (*crlEntry, error) {
	entry := &crlEntry{}
	actual, _ := m.entries.LoadOrStore(uri, entry)
	return actual.(*crlEntry), nil
}

type DownloadableCrlManager struct {
	CommonCrlManager
	client *http.Client

	// RefreshInterval controls how often a cached CRL is considered stale and
	// must be re-fetched. Defaults to 24 * 7 hour (1 week).
	RefreshInterval time.Duration
}

func (m *DownloadableCrlManager) downloadCRL(uri string) ([]byte, error) {
	resp, err := m.client.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
