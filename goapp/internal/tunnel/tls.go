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
	"fmt"
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

// GetLocalNodeCertPath returns the path where the probe node caches its TLS cert_pem downloaded from the Master.
func GetLocalNodeCertPath() string {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}
	certDir := filepath.Join(dataDir, "probe_cert")
	os.MkdirAll(certDir, 0o700)
	return filepath.Join(certDir, "cert.pem")
}

// GetLocalNodeKeyPath returns the path where the probe node caches its TLS key_pem downloaded from the Master.
func GetLocalNodeKeyPath() string {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}
	certDir := filepath.Join(dataDir, "probe_cert")
	os.MkdirAll(certDir, 0o700)
	return filepath.Join(certDir, "key.pem")
}

// GetCertInfo reads the stored certificate from DB and returns parsed status info.
func GetCertInfo(dbConn *sql.DB) *CertInfo {
	settings, err := store.GetSettings(dbConn, []string{
		"probe_auto_tls", "probe_tls_cert_pem",
		"probe_ddns_domain", "probe_public_address",
	})
	if err != nil || settings["probe_auto_tls"] != "true" {
		return nil
	}

	domain := strings.ToLower(settings["probe_ddns_domain"])
	if domain == "" {
		domain = strings.ToLower(settings["probe_public_address"])
	}

	certPEMStr := settings["probe_tls_cert_pem"]
	if certPEMStr == "" {
		return nil // TLS enabled but no cert yet -> template shows pending
	}

	certPEM := []byte(certPEMStr)

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	info := &CertInfo{Domain: domain}

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

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func loadOrCreateUser(cacheDir, domain string) (*acmeUser, error) {
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

	email := "admin@" + domain

	u := &acmeUser{
		Email: email,
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
	domain = strings.ToLower(domain)
	log.Printf("[TLS] Requesting Let's Encrypt certificate via DNS-01 for domain: %s", domain)

	// Mark as running in DB
	now := time.Now().Format("2006-01-02 15:04:05")
	_ = store.SetSetting(dbConn, "probe_tls_cert_status", "running")
	_ = store.SetSetting(dbConn, "probe_tls_cert_error", "")
	_ = store.SetSetting(dbConn, "probe_tls_cert_updated_at", now)

	certRes, err := executeACMERequest(dbConn, domain)
	if err != nil {
		msg := fmt.Sprintf("DNS-01 验证或证书申请失败: %v", err)
		log.Printf("[TLS] %s", msg)
		_ = store.SetSetting(dbConn, "probe_tls_cert_status", "error")
		_ = store.SetSetting(dbConn, "probe_tls_cert_error", msg)
		return
	}

	// Save the obtained certificate & key straight to DB
	_ = store.SetSetting(dbConn, "probe_tls_cert_pem", string(certRes.Certificate))
	_ = store.SetSetting(dbConn, "probe_tls_key_pem", string(certRes.PrivateKey))
	_ = store.SetSetting(dbConn, "probe_tls_cert_status", "success")
	_ = store.SetSetting(dbConn, "probe_tls_cert_error", "")
	_ = store.SetSetting(dbConn, "probe_tls_cert_updated_at", time.Now().Format("2006-01-02 15:04:05"))

	log.Printf("[TLS] Certificate for %s successfully issued and stored in database", domain)
}

// RequestNodeCertificate retrieves a Let's Encrypt cert via DNS-01 for a specific Probe Node and securely stores it in its database record.
func RequestNodeCertificate(dbConn *sql.DB, nodeID int64, domain string) {
	domain = strings.ToLower(domain)
	log.Printf("[TLS] Requesting Let's Encrypt certificate via DNS-01 for Probe Node %d: %s", nodeID, domain)

	certRes, err := executeACMERequest(dbConn, domain)
	if err != nil {
		log.Printf("[TLS] Failed to request cert for Probe Node %d (%s): %v", nodeID, domain, err)
		return
	}

	// Parse cert to find exact expiration date
	expiredAt := ""
	block, _ := pem.Decode(certRes.Certificate)
	if block != nil {
		if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
			expiredAt = leaf.NotAfter.Format("2006-01-02 15:04:05")
		}
	}

	err = store.UpdateProbeNodeTLS(dbConn, nodeID, domain, string(certRes.Certificate), string(certRes.PrivateKey), expiredAt)
	if err != nil {
		log.Printf("[TLS] Failed to store cert for Probe Node %d (%s) into database: %v", nodeID, domain, err)
		return
	}

	log.Printf("[TLS] Certificate for Probe Node %d (%s) successfully issued and securely stored in database", nodeID, domain)
}

// executeACMERequest holds the common lego DNS-01 ACME logic.
func executeACMERequest(dbConn *sql.DB, domain string) (*certificate.Resource, error) {
	settings, err := store.GetSettings(dbConn, []string{"cf_api_token"})
	if err != nil || strings.TrimSpace(settings["cf_api_token"]) == "" {
		return nil, fmt.Errorf("cf_api_token 未配置，无法使用 DNS-01 申请证书")
	}
	cfToken := strings.TrimSpace(settings["cf_api_token"])

	cacheDir := certCacheDir()
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建缓存目录失败: %v", err)
	}

	user, err := loadOrCreateUser(cacheDir, domain)
	if err != nil {
		return nil, fmt.Errorf("ACME 账号创建失败: %v", err)
	}

	// 1. ACME Configuration
	config := lego.NewConfig(user)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("ACME 客户端创建失败: %v", err)
	}

	// 2. Setup Cloudflare DNS Provider
	cfConfig := cf_provider.NewDefaultConfig()
	cfConfig.AuthToken = cfToken
	provider, err := cf_provider.NewDNSProviderConfig(cfConfig)
	if err != nil {
		return nil, fmt.Errorf("Cloudflare DNS Provider 创建失败（请检查 CF API Token 权限）: %v", err)
	}
	client.Challenge.SetDNS01Provider(provider)

	// 3. Register Account if not already registered
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("Let's Encrypt 账号注册失败: %v", err)
		}
		user.Registration = reg
		saveUserReg(cacheDir, user)
		log.Printf("[TLS] Registered ACME account")
	}

	// 4. Obtain new cert via DNS-01
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	return client.Certificate.Obtain(request)
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

	domain := strings.ToLower(settings["probe_ddns_domain"])
	if domain == "" {
		domain = strings.ToLower(settings["probe_public_address"])
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

// GetTLSConfig returns a *tls.Config that loads the stored cert/key from the DB.
func GetTLSConfig(dbConn *sql.DB) *tls.Config {
	settings, err := store.GetSettings(dbConn, []string{
		"probe_auto_tls", "probe_tls_cert_pem", "probe_tls_key_pem",
	})
	if err != nil || settings["probe_auto_tls"] != "true" {
		return nil
	}

	certPEM := settings["probe_tls_cert_pem"]
	keyPEM := settings["probe_tls_key_pem"]
	if certPEM == "" || keyPEM == "" {
		return nil
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		log.Printf("[TLS] Failed to load cert/key pair from DB: %v", err)
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
