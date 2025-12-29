package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func LoadRSAPrivateKeyPEM(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	// PKCS1
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}

	// PKCS8
	if any, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if k, ok := any.(*rsa.PrivateKey); ok {
			return k, nil
		}
		return nil, errors.New("private key is not RSA")
	}

	return nil, errors.New("unsupported private key format (expected PKCS1 or PKCS8)")
}

func LoadRSAPublicKeyPEM(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	// PKIX
	if any, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if k, ok := any.(*rsa.PublicKey); ok {
			return k, nil
		}
		return nil, errors.New("public key is not RSA")
	}

	// PKCS1
	if k, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return k, nil
	}

	return nil, errors.New("unsupported public key format (expected PKIX or PKCS1)")
}
