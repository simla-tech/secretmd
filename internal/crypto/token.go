package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

const (
	TokenVersion = 1
	TokenAlg     = "RSA-OAEP-SHA256+AES-256-GCM"
)

type TokenEnvelope struct {
	V     int    `json:"v"`
	Alg   string `json:"alg"`
	EK    string `json:"ek"`    // base64(RSA_OAEP(pub, dataKey))
	Nonce string `json:"nonce"` // base64(nonce)
	CT    string `json:"ct"`    // base64(ciphertext||tag)
}

// EncryptToToken encrypts plaintext bytes using AES-256-GCM and wraps the AES key with RSA-OAEP-SHA256.
// Output is base64url(JSON envelope) without padding.
func EncryptToToken(pub *rsa.PublicKey, plaintext []byte) (string, error) {
	// dataKey (AES-256)
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return "", err
	}

	// AES-GCM
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize()) // typically 12
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	// RSA-OAEP wrap dataKey
	ek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dataKey, nil)
	if err != nil {
		return "", err
	}

	env := TokenEnvelope{
		V:     TokenVersion,
		Alg:   TokenAlg,
		EK:    base64.StdEncoding.EncodeToString(ek),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}

	j, err := json.Marshal(env)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(j), nil
}

func DecryptFromToken(priv *rsa.PrivateKey, token string) ([]byte, error) {
	j, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	var env TokenEnvelope
	if err := json.Unmarshal(j, &env); err != nil {
		return nil, err
	}
	if env.V != TokenVersion || env.Alg != TokenAlg {
		return nil, errors.New("unsupported token version/alg")
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

	return gcm.Open(nil, nonce, ct, nil)
}
