package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"os"

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
		cmdEncryptMD(os.Args[2:])
	case "decrypt":
		cmdDecryptMD(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`secretmd — шифрование секретов прямо в Markdown.
	
Каждый секрет шифруется случайным симметричным AES-256 ключом, который в свою очередь зашифровывается переданным RSA ключом. Такой подход позволяет шифровать секреты произвольный длины.

Маркер plaintext в markdown файле:
  !encrypt{MY_SECRET}

Маркер ciphertext в markdown файле:
  !secret{<TOKEN>}
  где <TOKEN> = base64url(JSON конверт), внутри:
    - ek 	= RSA-OAEP-SHA256(pub, dataKey)
    - nonce = AES-GCM nonce
    - ct    = AES-256-GCM(ciphertext||tag)

Команды:
  encrypt --root <DIR> (--pub <PUBLIC_PEM> | --priv <PRIVATE_PEM>)
      Рекурсивно проходит по *.md файлам в <DIR>, находит !encrypt{...} и заменяет на !secret{...}.
      Перезаписывает файлы на месте.

  decrypt --file <FILE.md> --priv <PRIVATE_PEM>
      Выводит содержимое файла в stdout с дешифрованными !secret{...}.

Примеры:
  secretmd encrypt --root docs --pub keys/public.pem
  secretmd decrypt --file docs/setup.md --priv keys/private.pem
`)
}

func cmdEncryptMD(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	root := fs.String("root", ".", "directory to recursively scan for *.md")
	pubPath := fs.String("pub", "", "RSA public key PEM (recommended)")
	privPath := fs.String("priv", "", "RSA private key PEM (optional; derives public key)")
	fs.Parse(args)

	pub, err := loadPublic(*pubPath, *privPath)
	if err != nil {
		fatal(err)
	}

	var changedFiles int
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

		changedFiles++
		return os.WriteFile(path, out, 0644)
	})
	if err != nil {
		fatal(err)
	}

	fmt.Printf("Encryption complete. Files changed: %d\n", changedFiles)
}

func cmdDecryptMD(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	filePath := fs.String("file", "", "single markdown file to decrypt and print to stdout")
	privPath := fs.String("priv", "", "RSA private key PEM")
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

	in, err := os.ReadFile(*filePath)
	if err != nil {
		fatal(err)
	}

	out, _, err := mdsecrets.DecryptMarkdown(priv, in)
	if err != nil {
		fatal(fmt.Errorf("%s: %w", *filePath, err))
	}

	_, err = os.Stdout.Write(out)
	if err == nil && len(out) > 0 && out[len(out)-1] != '\n' {
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
