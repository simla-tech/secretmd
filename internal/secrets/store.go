package secrets

import (
	"crypto/rsa"
	"os"

	"secretmd/internal/crypto"

	"gopkg.in/yaml.v3"
)

func EncryptFile(pub *rsa.PublicKey, inPlainYAML, outEncYAML string) error {
	plain, err := os.ReadFile(inPlainYAML)
	if err != nil {
		return err
	}

	env, err := crypto.EncryptRSAOAEP_AESGCM(pub, plain)
	if err != nil {
		return err
	}

	b, err := yaml.Marshal(env)
	if err != nil {
		return err
	}
	return os.WriteFile(outEncYAML, b, 0644)
}

func DecryptFile(priv *rsa.PrivateKey, inEncYAML, outPlainYAML string) error {
	b, err := os.ReadFile(inEncYAML)
	if err != nil {
		return err
	}

	var env crypto.EnvelopeYAML
	if err := yaml.Unmarshal(b, &env); err != nil {
		return err
	}

	plain, err := crypto.DecryptRSAOAEP_AESGCM(priv, &env)
	if err != nil {
		return err
	}

	// plaintext file: protect a bit more
	return os.WriteFile(outPlainYAML, plain, 0600)
}

func LoadDecryptedMap(priv *rsa.PrivateKey, inEncYAML string) (map[string]any, error) {
	b, err := os.ReadFile(inEncYAML)
	if err != nil {
		return nil, err
	}

	var env crypto.EnvelopeYAML
	if err := yaml.Unmarshal(b, &env); err != nil {
		return nil, err
	}

	plain, err := crypto.DecryptRSAOAEP_AESGCM(priv, &env)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := yaml.Unmarshal(plain, &m); err != nil {
		return nil, err
	}
	return m, nil
}
