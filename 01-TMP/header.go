package crlenforcer

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
)

const headerTLSClientCert = "X-Forwarded-Tls-Client-Cert"

// encodeCertHeader encode le certificat en PEM puis l'échappe exactement
// comme le fait le middleware natif passTLSClientCert de Traefik :
// suppression des délimiteurs et des newlines, puis URL-encoding.
func encodeCertHeader(cert *x509.Certificate) (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if pemBytes == nil {
		return "", fmt.Errorf("failed to PEM-encode certificate")
	}

	s := string(pemBytes)
	s = strings.ReplaceAll(s, "-----BEGIN CERTIFICATE-----", "")
	s = strings.ReplaceAll(s, "-----END CERTIFICATE-----", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.TrimSpace(s)

	return url.QueryEscape(s), nil
}
