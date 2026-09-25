package crlenforcer

import (
	"crypto/x509"
	"net/http"
)

type CrlManager interface {
	getVerifiedSnapshot(uri string, issuer *x509.Certificate) (*crlSnapshot, error)
	getOrCreateEntry(uri string) (*crlEntry, error)
}

func NewFailedCloseSnapManager(cfg *Config) CrlManager {
	return &FaileClosedSnapshotManager{
		DownloadableCrlManager: DownloadableCrlManager{
			RefreshInterval: cfg.RefreshInterval,
			client: &http.Client{
				Timeout: cfg.HTTPTimeout,
			},
		},
	}
}

func NewOpenSnapManager(cfg *Config) CrlManager {
	return &OpenSnapshotManager{
		DownloadableCrlManager: DownloadableCrlManager{
			RefreshInterval: cfg.RefreshInterval,
			client: &http.Client{
				Timeout: cfg.HTTPTimeout,
			},
		},
	}
}
