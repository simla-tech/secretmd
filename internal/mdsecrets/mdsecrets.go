package mdsecrets

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"regexp"
	"strings"

	"secretmd/internal/crypto"
)

// Secret markdown markers
var (
	reEncryptPlain = regexp.MustCompile(`(?s)!encrypt\s*\{\s*(.*?)\s*\}`)
	reSecretEnc = regexp.MustCompile(`(?s)!secret\s*\{\s*([A-Za-z0-9\-_]+)\s*\}`)
)

func EncryptMarkdown(pub *rsa.PublicKey, in []byte) ([]byte, bool, error) {
	out := in
	changed := false

	var err error
	out, changed1, err := replacePlainWithSecret(pub, out, reEncryptPlain)
	if err != nil {
		return nil, false, err
	}
	changed = changed || changed1

	return out, changed, nil
}

func replacePlainWithSecret(pub *rsa.PublicKey, in []byte, re *regexp.Regexp) ([]byte, bool, error) {
	matches := re.FindAllSubmatchIndex(in, -1)
	if len(matches) == 0 {
		return in, false, nil
	}

	out := in
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		start, end := m[0], m[1]
		innerStart, innerEnd := m[2], m[3]

		plain := out[innerStart:innerEnd]
		// preserve exactly as typed inside braces, but strip only surrounding whitespace already handled by regex
		token, err := crypto.EncryptToToken(pub, plain)
		if err != nil {
			return nil, false, err
		}

		repl := []byte("!secret{" + token + "}")
		out = bytes.Join([][]byte{out[:start], repl, out[end:]}, nil)
	}
	return out, true, nil
}

func DecryptMarkdown(priv *rsa.PrivateKey, in []byte) ([]byte, bool, error) {
	matches := reSecretEnc.FindAllSubmatchIndex(in, -1)
	if len(matches) == 0 {
		return in, false, nil
	}

	out := in
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		start, end := m[0], m[1]
		innerStart, innerEnd := m[2], m[3]

		token := strings.TrimSpace(string(out[innerStart:innerEnd]))
		plain, err := crypto.DecryptFromToken(priv, token)
		if err != nil {
			return nil, false, fmt.Errorf("decrypt token failed: %w", err)
		}

		repl := []byte(string(plain))
		out = bytes.Join([][]byte{out[:start], repl, out[end:]}, nil)
	}

	return out, true, nil
}
