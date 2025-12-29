package render

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"secretmd/internal/fswalk"
	"secretmd/internal/secrets"

	"gopkg.in/yaml.v3"
)

var rePlaceholder = regexp.MustCompile(`\{\{\s*secret\s+\"([^\"]+)\"\s*\}\}`)

func RenderDocs(priv *rsa.PrivateKey, docsDir, encSecretsPath, outDir string) error {
	absDocs, err := filepath.Abs(docsDir)
	if err != nil {
		return err
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	if absDocs == absOut || strings.HasPrefix(absOut, absDocs+string(os.PathSeparator)) {
		return errors.New("--out must be outside --docs (use something like .rendered)")
	}

	secMap, err := secrets.LoadDecryptedMap(priv, encSecretsPath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(absOut, 0755); err != nil {
		return err
	}

	return fswalk.WalkMarkdown(absDocs, func(path string) error {
		in, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		out, err := replaceAll(in, secMap)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		rel, _ := filepath.Rel(absDocs, path)
		outPath := filepath.Join(absOut, rel)
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return err
		}
		return os.WriteFile(outPath, out, 0644)
	})
}

func replaceAll(in []byte, sec map[string]any) ([]byte, error) {
	matches := rePlaceholder.FindAllSubmatchIndex(in, -1)
	if len(matches) == 0 {
		return in, nil
	}

	out := in
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		start, end := m[0], m[1]
		keyStart, keyEnd := m[2], m[3]
		path := string(out[keyStart:keyEnd])

		val, ok := lookup(sec, path)
		if !ok {
			return nil, fmt.Errorf("secret not found: %q", path)
		}
		repl, err := stringify(val)
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", path, err)
		}

		out = bytes.Join([][]byte{out[:start], []byte(repl), out[end:]}, nil)
	}
	return out, nil
}

func lookup(m map[string]any, dotted string) (any, bool) {
	parts := strings.Split(dotted, ".")
	var cur any = m
	for _, p := range parts {
		mp, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mp[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func stringify(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "", nil
	case string:
		return t, nil
	case bool, int, int64, float64, uint64:
		return fmt.Sprint(t), nil
	default:
		b, err := yaml.Marshal(t)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
}
