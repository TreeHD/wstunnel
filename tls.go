// tls.go — TLS 自簽憑證生成 + SNI 白名單
//
// 職責：
//   * 第一次啟動時自動產生 self-signed 憑證
//   * 載入既有憑證
//   * SNI 白名單比對
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)

const (
	certFile = "cert.pem"
	keyFile  = "key.pem"
)

// generateOrLoadTLSConfig 產生或載入伺服器端 TLS 憑證
func generateOrLoadTLSConfig() (*tls.Config, error) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("System: TLS certificate not found. Generating a new self-signed certificate...")
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, fmt.Errorf("failed to generate serial number: %w", err)
		}
		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{Organization: []string{"WSTunnel Self-Signed"}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate: %w", err)
		}
		certOut, err := os.Create(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open cert.pem for writing: %w", err)
		}
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()
		log.Printf("System: Saved certificate to %s", certFile)

		keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open key.pem for writing: %w", err)
		}
		privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
		pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		keyOut.Close()
		log.Printf("System: Saved private key to %s", keyFile)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// isSNIAllowed 比對 SNI 是否在白名單
// 空白名單代表全部放行
func isSNIAllowed(sni string) bool {
	globalConfig.lock.RLock()
	defer globalConfig.lock.RUnlock()
	if len(globalConfig.AllowedSNI) == 0 {
		return true
	}
	for _, allowed := range globalConfig.AllowedSNI {
		if strings.EqualFold(allowed, sni) {
			return true
		}
	}
	return false
}
