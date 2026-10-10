package capsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	privPEM, pubPEM, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"schemaVersion":"capability.v1"}`)
	sig, err := Sign(privPEM, msg)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != 64 {
		t.Fatalf("fingerprint = %q (want 64 hex)", fp)
	}
	// Verify with stdlib ecdsa (the registry's scheme): base64 ASN.1 over
	// sha256(message).
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatal("public key is not PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pubAny.(*ecdsa.PublicKey), digest[:], raw) {
		t.Fatal("signature does not verify against the public key")
	}
	// PublicKeyOf derives the matching public PEM.
	derived, err := PublicKeyOf(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := Fingerprint(derived)
	if err != nil {
		t.Fatal(err)
	}
	if fp2 != fp {
		t.Fatalf("derived public key fingerprint %q != %q", fp2, fp)
	}
	if !bytes.Equal(bytes.TrimSpace(derived), bytes.TrimSpace(pubPEM)) {
		t.Fatalf("derived public key differs:\n%s\nvs\n%s", derived, pubPEM)
	}
}
