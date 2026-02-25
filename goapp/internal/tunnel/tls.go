package tunnel

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	cf_provider "github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"

	"vpshelper-go/internal/store"
)

// CertInfo holds human-readable information about the current TLS certificate.
type CertInfo struct {
	Domain    string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	DaysLeft  int
	IsValid   bool
}

// certCacheDir returns the directory used to cache certificates and ACME account keys.
func certCacheDir() string {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}
	return filepath.Join(dataDir, "autocert_dns01")
}

// GetCertInfo reads the stored certificate file and returns parsed status info.
func GetCertInfo(dbConn *sql.DB) *CertInfo {
	settings, err := store.GetSettings(dbConn, []string{
		"probe_auto_tls", "probe_tls_cert_path",
		"probe_ddns_domain", "probe_public_address",
	})
	if err != nil || settings["probe_auto_tls"] != "true" {
		return nil
	}

	domain := settings["probe_ddns_domain"]
	if domain == "" {
		domain = settings["probe_public_address"]
	}

	info := &CertInfo{Domain: domain}

	certPath := settings["probe_tls_cert_path"]
	if certPath == "" {
		return info // TLS enabled but no cert yet
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return info
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return info
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return info
	}

	now := time.Now()
	info.NotBefore = leaf.NotBefore
	info.NotAfter = leaf.NotAfter
	info.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
	info.IsValid = now.Before(leaf.NotAfter) && now.After(leaf.NotBefore)
	info.Issuer = leaf.Issuer.CommonName
	return info
}

// ──────────────────────────────────────────────────────────────────────────────
// Let's Encrypt DNS-01 ACME Client (using lego)
// ──────────────────────────────────────────────────────────────────────────────

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                              { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource        { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey               { return u.key }

func loadOrCreateUser(cacheDir string) (*acmeUser, error) {
	keyPath := filepath.Join(cacheDir, "account.key")
	regPath := filepath.Join(cacheDir, "account.json")

	var key crypto.PrivateKey
	keyBytes, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			var parseErr error
			key, parseErr = x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				key = nil
			}
		}
	}

	if key == nil {
		// generate new key
		var ecKey *ecdsa.PrivateKey
		ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		key = ecKey
		der, _ := x509.MarshalPKCS8PrivateKey(ecKey)
		os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	}

	u := &acmeUser{
		Email: "admin@vpshelper.local",
		key:   key,
	}

	regBytes, err := os.ReadFile(regPath)
	if err == nil {
		var reg registration.Resource
		if json.Unmarshal(regBytes, &reg) == nil {
			u.Registration = &reg
		}
	}

	return u, nil
}

func saveUserReg(cacheDir string, u *acmeUser) {
	if u.Registration != nil {
		regPath := filepath.Join(cacheDir, "account.json")
		b, _ := json.MarshalIndent(u.Registration, "", "  ")
		os.WriteFile(regPath, b, 0o600)
	}
}

// RequestCertificate requests a regular Let's Encrypt cert using DNS-01 via Cloudflare API.
func RequestCertificate(dbConn *sql.DB, domain string) {
	log.Printf("[TLS] Requesting Let's Encrypt certificate via DNS-01 for domain: %s", domain)

	settings, err := store.GetSettings(dbConn, []string{"cf_api_token", "probe_tls_cert_path", "probe_tls_key_path"})
	if err != nil || strings.TrimSpace(settings["cf_api_token"]) == "" {
		log.Printf("[TLS] cf_api_token not configured — cannot request certificate via DNS-01")
		return
	}
	cfToken := strings.TrimSpace(settings["cf_api_token"])

	cacheDir := certCacheDir()
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		log.Printf("[TLS] Failed to create cert cache dir: %v", err)
		return
	}

	user, err := loadOrCreateUser(cacheDir)
	if err != nil {
		log.Printf("[TLS] ACME User error: %v", err)
		return
	}

	// 1. ACME Configuration
	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		log.Printf("[TLS] lego Client error: %v", err)
		return
	}

	// 2. Setup Cloudflare DNS Provider
	cfConfig := cf_provider.NewDefaultConfig()
	cfConfig.AuthToken = cfToken
	provider, err := cf_provider.NewDNSProviderConfig(cfConfig)
	if err != nil {
		log.Printf("[TLS] DNS Provider error: %v", err)
		return
	}
	client.Challenge.SetDNS01Provider(provider)

	// 3. Register Account if not already registered
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Printf("[TLS] ACME Register error: %v", err)
			return
		}
		user.Registration = reg
		saveUserReg(cacheDir, user)
		log.Printf("[TLS] Registered ACME account")
	}

	// 4. Check if we are really renewing or obtaining fresh
	certPath := filepath.Join(cacheDir, domain+".crt")
	keyPath := filepath.Join(cacheDir, domain+".key")

	var certRes *certificate.Resource
	
	// Obtain new cert via DNS-01
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certRes, err = client.Certificate.Obtain(request)
	if err != nil {
		log.Printf("[TLS] Failed to obtain cert: %v", err)
		return
	}

	// 5. Save the obtained certificate & key
	if err := os.WriteFile(certPath, certRes.Certificate, 0o644); err != nil {
		log.Printf("[TLS] Write cert file failed: %v", err)
		return
	}
	if err := os.WriteFile(keyPath, certRes.PrivateKey, 0o600); err != nil {
		log.Printf("[TLS] Write key file failed: %v", err)
		return
	}

	_ = store.SetSetting(dbConn, "probe_tls_cert_path", certPath)
	_ = store.SetSetting(dbConn, "probe_tls_key_path", keyPath)
	log.Printf("[TLS] Certificate for %s successfully issued and stored at %s", domain, certPath)
}

// StartRenewalWatcher starts a background goroutine that checks the certificate
// expiry every 24 hours and renews it automatically when fewer than 30 days remain.
func StartRenewalWatcher(ctx context.Context, dbConn *sql.DB) {
	go func() {
		checkAndRenew(dbConn)

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				checkAndRenew(dbConn)
			}
		}
	}()
}

func checkAndRenew(dbConn *sql.DB) {
	settings, err := store.GetSettings(dbConn, []string{
		"probe_auto_tls", "probe_ddns_domain", "probe_public_address",
	})
	if err != nil || settings["probe_auto_tls"] != "true" {
		return
	}

	domain := settings["probe_ddns_domain"]
	if domain == "" {
		domain = settings["probe_public_address"]
	}
	if domain == "" {
		return
	}

	info := GetCertInfo(dbConn)
	if info == nil || !info.IsValid {
		log.Printf("[TLS] No valid cert found for %s, requesting...", domain)
		RequestCertificate(dbConn, domain)
		return
	}

	if info.DaysLeft <= 30 {
		log.Printf("[TLS] Certificate for %s expires in %d days — renewing via DNS-01...", domain, info.DaysLeft)
		RequestCertificate(dbConn, domain)
	} else {
		log.Printf("[TLS] Certificate for %s is valid, %d days remaining.", domain, info.DaysLeft)
	}
}

// GetTLSConfig returns a *tls.Config that loads the stored cert/key files.
func GetTLSConfig(dbConn *sql.DB) *tls.Config {
	settings, err := store.GetSettings(dbConn, []string{
		"probe_auto_tls", "probe_tls_cert_path", "probe_tls_key_path",
	})
	if err != nil || settings["probe_auto_tls"] != "true" {
		return nil
	}

	certPath := settings["probe_tls_cert_path"]
	keyPath := settings["probe_tls_key_path"]
	if certPath == "" || keyPath == "" {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Printf("[TLS] Failed to load cert/key pair: %v", err)
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// selfSignedTLSConfig generates a throwaway self-signed TLS config for fallback/testing.
func selfSignedTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vpshelper-probe"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(87600 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		func() []byte {
			b, _ := x509.MarshalECPrivateKey(key)
			return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		}(),
	)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
