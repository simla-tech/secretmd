package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"os"

	"secretmd/internal/keys"
	"secretmd/internal/render"
	"secretmd/internal/secrets"
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
	case "render":
		cmdRender(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`secretmd — утилита для шифрования секретов перед сохранением в репозиторий, а также для рендеринга Markdown-шаблонов с автоматической расшифровкой секретов.

Криптосхема (как устроено шифрование)
  1) Входной файл (например, secrets.yaml) (plaintext) читается как набор байт (как есть).
  2) Генерируется случайный симметричный ключ dataKey (32 байта) для AES-256.
  3) Весь plaintext шифруется симметричным AES-256-GCM → получается ct (ciphertext + authentication tag).
  4) dataKey "оборачивается" (шифруется) публичным RSA ключом через RSA-OAEP-SHA256 → получается ek.
  5) Результат сохраняется в YAML-файл (например, secrets.enc.yaml) в виде "конверта" со следующими полями:
       v:     версия формата (сейчас 1)
       alg:   алгоритм (RSA-OAEP-SHA256+AES-256-GCM)
       ek:    base64( RSA-OAEP(pub, dataKey) )
       nonce: base64( nonce для AES-GCM )
       ct:    base64( AES-GCM(ciphertext||tag) )

Плейсхолдеры в Markdown
  {{ secret "path.to.value" }}
  где path.to.value — путь по ключам YAML через точку (например: smtp.password).

Команды (общий вид)
  secretmd encrypt --in <PLAINTEXT_YAML> --out <ENCRYPTED_YAML> (--pub <PUBLIC_PEM> | --priv <PRIVATE_PEM>)
      Шифрует plaintext YAML в encrypted YAML.
      Рекомендуется использовать --pub (публичный ключ). Если указан только --priv, публичный ключ будет взят из приватного.

  secretmd decrypt --in <ENCRYPTED_YAML> --out <PLAINTEXT_YAML> --priv <PRIVATE_PEM>
      Дешифрует encrypted YAML в plaintext YAML.

  secretmd render --docs <DOCS_DIR> --secrets <ENCRYPTED_YAML> --out <OUT_DIR> --priv <PRIVATE_PEM>
      Подставляет секреты в Markdown-файлы из DOCS_DIR по плейсхолдерам и пишет результат в OUT_DIR.

Примеры
  # 1) Шифрование (лучший вариант: только публичный ключ)
  secretmd encrypt --in secrets.yaml --out secrets.enc.yaml --pub keys/key.public

  # 2) Шифрование (если есть только приватный ключ; публичный берётся из него)
  secretmd encrypt --in secrets.yaml --out secrets.enc.yaml --priv keys/key.private

  # 3) Рендер документации в .rendered
  secretmd render --docs docs --secrets secrets.enc.yaml --out .rendered --priv keys/key.private

  # 4) Дешифрование в файл
  secretmd decrypt --in secrets.enc.yaml --out secrets.dec.yaml --priv keys/key.private
`)
}

func cmdEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	inPath := fs.String("in", "secrets.yaml", "plaintext secrets yaml (DO NOT COMMIT)")
	outPath := fs.String("out", "secrets.enc.yaml", "encrypted secrets yaml (safe to commit)")
	pubPath := fs.String("pub", "", "RSA public key PEM (recommended)")
	privPath := fs.String("priv", "", "RSA private key PEM (optional, used to derive public key)")
	fs.Parse(args)

	var pub *rsa.PublicKey
	var err error

	switch {
	case *pubPath != "":
		pub, err = keys.LoadRSAPublicKeyPEM(*pubPath)
		if err != nil {
			fatal(err)
		}
	case *privPath != "":
		priv, err := keys.LoadRSAPrivateKeyPEM(*privPath)
		if err != nil {
			fatal(err)
		}
		pub = &priv.PublicKey
	default:
		fatalf("encrypt requires --pub or --priv")
	}

	if err := secrets.EncryptFile(pub, *inPath, *outPath); err != nil {
		fatal(err)
	}
	fmt.Printf("Encrypted %s -> %s\n", *inPath, *outPath)
}

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	inPath := fs.String("in", "secrets.enc.yaml", "encrypted secrets yaml")
	outPath := fs.String("out", "secrets.dec.yaml", "output plaintext yaml (DO NOT COMMIT)")
	privPath := fs.String("priv", "", "RSA private key PEM")
	fs.Parse(args)

	if *privPath == "" {
		fatalf("--priv is required")
	}

	priv, err := keys.LoadRSAPrivateKeyPEM(*privPath)
	if err != nil {
		fatal(err)
	}

	if err := secrets.DecryptFile(priv, *inPath, *outPath); err != nil {
		fatal(err)
	}
	fmt.Printf("Decrypted %s -> %s\n", *inPath, *outPath)
}

func cmdRender(args []string) {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	docsDir := fs.String("docs", "docs", "directory with markdown templates")
	encSecrets := fs.String("secrets", "secrets.enc.yaml", "encrypted secrets file")
	outDir := fs.String("out", ".rendered", "output dir for rendered markdown (gitignored)")
	privPath := fs.String("priv", "", "RSA private key PEM")
	fs.Parse(args)

	if *privPath == "" {
		fatalf("--priv is required")
	}
	priv, err := keys.LoadRSAPrivateKeyPEM(*privPath)
	if err != nil {
		fatal(err)
	}

	if err := render.RenderDocs(priv, *docsDir, *encSecrets, *outDir); err != nil {
		fatal(err)
	}
	fmt.Printf("Rendered %s -> %s\n", *docsDir, *outDir)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}
func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", a...)
	os.Exit(1)
}
