package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"secretmd/internal/crypto"
	"secretmd/internal/fswalk"
	"secretmd/internal/keys"
	"secretmd/internal/mdsecrets"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "encrypt":
		cmdEncrypt(os.Args[2:])
	case "decrypt":
		cmdDecrypt(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`secretmd — шифрование секретов в Markdown и внешних файлах.

Inline маркеры в Markdown:
  plaintext:  !encrypt{...}
  ciphertext: !secret{<TOKEN>}

Внешние файлы (опционально):
  *.encrypt  -> шифруется целиком и заменяется на *.secret
  *.secret   -> содержит <TOKEN> (base64url JSON envelope), один токен на файл

Команды:
  encrypt --root <DIR> (--pub <PUBLIC_PEM> | --priv <PRIVATE_PEM>) [--encrypt-external-files]
  decrypt --file <PATH> --priv <PRIVATE_PEM> [--export-dir <OUT_DIR>]

Примеры:
  secretmd encrypt --root docs --pub keys/public.pem
  secretmd encrypt --root docs --pub keys/public.pem --encrypt-external-files

  secretmd decrypt --file docs/setup.md --priv keys/private.pem
  secretmd decrypt --file artifacts/config.secret --priv keys/private.pem
  secretmd decrypt --file artifacts/config.secret --priv keys/private.pem --export-dir ./out
`)
}

func cmdEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	root := fs.String("root", ".", "directory to recursively scan")
	pubPath := fs.String("pub", "", "RSA public key PEM (recommended)")
	privPath := fs.String("priv", "", "RSA private key PEM (optional; derives public key)")
	encryptExternal := fs.Bool("encrypt-external-files", false, "also encrypt *.encrypt files into *.secret")
	fs.Parse(args)

	pub, err := loadPublic(*pubPath, *privPath)
	if err != nil {
		fatal(err)
	}

	// 1) Encrypt inline secrets in *.md
	var changedMD int
	err = fswalk.WalkMarkdown(*root, func(path string) error {
		in, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out, changed, err := mdsecrets.EncryptMarkdown(pub, in)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if !changed {
			return nil
		}
		changedMD++
		return os.WriteFile(path, out, 0644)
	})
	if err != nil {
		fatal(err)
	}

	// 2) Optionally encrypt external *.encrypt files -> *.secret
	var changedExt int
	if *encryptExternal {
		err = fswalk.WalkByExt(*root, ".encrypt", func(path string) error {
			in, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			token, err := crypto.EncryptToToken(pub, in)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}

			info, err := os.Stat(path)
			if err != nil {
				return err
			}

			newPath := strings.TrimSuffix(path, ".encrypt") + ".secret"
			// write new file first
			if err := os.WriteFile(newPath, []byte(token+"\n"), info.Mode()); err != nil {
				return err
			}
			// remove old file
			if err := os.Remove(path); err != nil {
				return err
			}

			changedExt++
			return nil
		})
		if err != nil {
			fatal(err)
		}
	}

	if *encryptExternal {
		fmt.Printf("Encryption complete. Markdown files changed: %d; external files converted: %d\n", changedMD, changedExt)
	} else {
		fmt.Printf("Encryption complete. Markdown files changed: %d\n", changedMD)
	}
}

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	filePath := fs.String("file", "", "single file to decrypt (.md or .secret)")
	privPath := fs.String("priv", "", "RSA private key PEM")
	exportDir := fs.String("export-dir", "", "for .secret: write plaintext to this directory (filename = input without .secret)")
	fs.Parse(args)

	if *filePath == "" {
		fatalf("--file is required")
	}
	if *privPath == "" {
		fatalf("--priv is required")
	}

	priv, err := keys.LoadRSAPrivateKeyPEM(*privPath)
	if err != nil {
		fatal(err)
	}

	ext := strings.ToLower(filepath.Ext(*filePath))
	switch ext {
	case ".md":
		in, err := os.ReadFile(*filePath)
		if err != nil {
			fatal(err)
		}
		out, _, err := mdsecrets.DecryptMarkdown(priv, in)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", *filePath, err))
		}
		writeToStdout(out)

	case ".secret":
		b, err := os.ReadFile(*filePath)
		if err != nil {
			fatal(err)
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			fatalf("%s: empty token", *filePath)
		}

		plain, err := crypto.DecryptFromToken(priv, token)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", *filePath, err))
		}

		if *exportDir != "" {
			if err := os.MkdirAll(*exportDir, 0755); err != nil {
				fatal(err)
			}

			base := filepath.Base(*filePath) // e.g. cert.pem.secret
			outName := strings.TrimSuffix(base, ".secret")
			if outName == base {
				fatalf("%s: expected .secret suffix", *filePath)
			}
			outPath := filepath.Join(*exportDir, outName)

			if err := os.WriteFile(outPath, plain, 0600); err != nil {
				fatal(err)
			}
		} else {
			writeToStdout(plain)
		}

	default:
		fatalf("unsupported file type: %s (expected .md or .secret)", ext)
	}
}

func writeToStdout(b []byte) {
	_, err := os.Stdout.Write(b)
	if err == nil && len(b) > 0 && b[len(b)-1] != '\n' {
		_, _ = os.Stdout.Write([]byte("\n"))
	}
	if err != nil {
		fatal(err)
	}
}

func loadPublic(pubPath, privPath string) (*rsa.PublicKey, error) {
	if pubPath != "" {
		return keys.LoadRSAPublicKeyPEM(pubPath)
	}
	if privPath != "" {
		priv, err := keys.LoadRSAPrivateKeyPEM(privPath)
		if err != nil {
			return nil, err
		}
		return &priv.PublicKey, nil
	}
	return nil, fmt.Errorf("encrypt requires --pub or --priv")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}
func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", a...)
	os.Exit(1)
}
