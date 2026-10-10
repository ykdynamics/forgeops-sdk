// Package capsign provides the developer-side P-256 ECDSA signing for
// Capability Packages, matching the registry's
// publisher-key format: PEM PKIX P-256 public keys,
// a fingerprint of sha256(raw PKIX DER) hex, and a signature that is base64
// ECDSA-ASN.1 over sha256 of the canonical manifest.
package capsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// GenerateKey creates a new P-256 keypair: the private key is PEM PKCS8
// (SEC 1), the public key PEM PKIX — the form the registry accepts.
func GenerateKey() (privatePEM, publicPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privatePEM, publicPEM, nil
}

// Sign signs message with the PEM PKCS8 P-256 private key and returns the
// base64 ECDSA-ASN.1 signature over sha256(message) — exactly what the
// registry verifies for a signed registration/evidence.
func Sign(privateKeyPEM, message []byte) (string, error) {
	priv, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Fingerprint derives the registry key identity from a PEM PKIX P-256 public
// key: sha256 of the raw PKIX DER bytes, hex-encoded.
func Fingerprint(publicKeyPEM []byte) (string, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", fmt.Errorf("public key is not valid PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return "", fmt.Errorf("public key is not a valid PKIX key: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// PublicKeyOf returns the PEM PKIX public key for a PEM PKCS8 private key.
func PublicKeyOf(privateKeyPEM []byte) ([]byte, error) {
	priv, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func parsePrivateKey(privateKeyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("private key is not valid PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("private key is not a P-256 ECDSA key")
	}
	return priv, nil
}
