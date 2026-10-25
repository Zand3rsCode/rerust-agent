// Package tlscert makes and loads the agent's own certificate. It is self-signed: the panel learns it at pairing (its
// sha256 fingerprint is part of the pairing code) and from then on trusts exactly this certificate - so no domain,
// port 80 or Let's Encrypt is needed, and HTTPS is still verified.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/config"
)

// Files is where the certificate and its key are kept.
type Files struct{ Cert, Key string }

// In returns the files inside the state folder.
func In(stateDir string) Files {
	return Files{Cert: filepath.Join(stateDir, "tls", "cert.pem"), Key: filepath.Join(stateDir, "tls", "key.pem")}
}

// Ensure makes the certificate when there is none yet. It is valid for 20 years: the panel pins it, so renewing
// would mean pairing again.
func Ensure(f Files) error {
	if _, err := os.Stat(f.Cert); err == nil {
		if _, err := os.Stat(f.Key); err == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ReRust Agent " + host, Organization: []string{"ReRust Agent"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // its own trust anchor: the panel uses it as the only CA for this machine
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	if host != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := config.WriteAtomic(f.Key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return config.WriteAtomic(f.Cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// Load reads the certificate for the HTTPS server.
func Load(f Files) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(f.Cert, f.Key)
}

// Fingerprint is the sha256 of the certificate (DER) - what the pairing code carries.
func Fingerprint(f Files) ([]byte, error) {
	raw, err := os.ReadFile(f.Cert)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate in " + f.Cert)
	}
	sum := sha256.Sum256(block.Bytes)
	return sum[:], nil
}
