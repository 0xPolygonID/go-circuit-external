package anonaadhaar

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var ErrInvalidSignature = errors.New("invalid public key")

// verifySignature checks whether the given data was signed with the RSA private key
// corresponding to the provided PEM-encoded public key, using RSA PKCS#1 v1.5 with SHA-256.
func verifySignature(data, signature []byte, keyPem string) error {
	block, _ := pem.Decode([]byte(keyPem))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	digest := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	return nil
}
