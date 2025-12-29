package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

const (
	EnvelopeVersion = 1
	EnvelopeAlg     = "RSA-OAEP-SHA256+AES-256-GCM"
)

// EnvelopeYAML is stored in secrets.enc.yaml
type EnvelopeYAML struct {
	V     int    `yaml:"v"`
	Alg   string `yaml:"alg"`
	EK    string `yaml:"ek"`    // base64(RSA_OAEP(pub, dataKey))
	Nonce string `yaml:"nonce"` // base64(nonce)
	CT    string `yaml:"ct"`    // base64(ciphertext||tag)
}

func EncryptRSAOAEP_AESGCM(pub *rsa.PublicKey, plaintext []byte) (*EnvelopeYAML, error) {
	// dataKey (AES-256)
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, err
	}

	// AES-GCM
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	// RSA-OAEP wrap dataKey
	ek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dataKey, nil)
	if err != nil {
		return nil, err
	}

	return &EnvelopeYAML{
		V:     EnvelopeVersion,
		Alg:   EnvelopeAlg,
		EK:    base64.StdEncoding.EncodeToString(ek),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}, nil
}

func DecryptRSAOAEP_AESGCM(priv *rsa.PrivateKey, env *EnvelopeYAML) ([]byte, error) {
	if env.V != EnvelopeVersion || env.Alg != EnvelopeAlg {
		return nil, errors.New("unsupported envelope version/alg")
	}

	ek, err := base64.StdEncoding.DecodeString(env.EK)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, err
	}

	dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ek, nil)
	if err != nil {
		return nil, err
	}
	if len(dataKey) != 32 {
		return nil, errors.New("bad data key length")
	}

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("bad nonce size")
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
