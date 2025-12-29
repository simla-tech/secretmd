secretmd — утилита для шифрования секретов перед сохранением в репозиторий, а также для рендеринга Markdown-шаблонов с автоматической расшифровкой секретов.

## Криптосхема (как устроено шифрование)

1) Входной файл (например, `secrets.yaml`) (plaintext) читается как набор байт (как есть).  
2) Генерируется случайный симметричный ключ `dataKey` (32 байта) для AES-256.  
3) Весь plaintext шифруется симметричным `AES-256-GCM` → получается `ct` (*ciphertext + authentication tag*).  
4) `dataKey` "оборачивается" (шифруется) публичным RSA ключом через `RSA-OAEP-SHA256` → получается `ek`.  
5) Результат сохраняется в YAML-файл (например, `secrets.enc.yaml`) в виде "конверта" со следующими полями:

- `v`: версия формата (сейчас 1)  
- `alg`: алгоритм (`RSA-OAEP-SHA256+AES-256-GCM`)  
- `ek`: `base64( RSA-OAEP(pub, dataKey) )`  
- `nonce`: `base64( nonce для AES-GCM )`  
- `ct`: `base64( AES-GCM(ciphertext||tag) )`

## Плейсхолдеры в Markdown

```
{{ secret "path.to.value" }}
```

Где `path.to.value` — путь по ключам YAML через точку (например: `smtp.password`).

## Команды

### Encrypt

```
secretmd encrypt --in <PLAINTEXT_YAML> --out <ENCRYPTED_YAML> (--pub <PUBLIC_PEM> | --priv <PRIVATE_PEM>)
```

Шифрует plaintext YAML в encrypted YAML.  
Рекомендуется использовать `--pub` (публичный ключ). Если указан только `--priv`, публичный ключ будет взят из приватного.

### Decrypt

```
secretmd decrypt --in <ENCRYPTED_YAML> --out <PLAINTEXT_YAML> --priv <PRIVATE_PEM>
```

Дешифрует encrypted YAML в plaintext YAML.

### Render

```
secretmd render --docs <DOCS_DIR> --secrets <ENCRYPTED_YAML> --out <OUT_DIR> --priv <PRIVATE_PEM>
```

Подставляет секреты в Markdown-файлы из `DOCS_DIR` по плейсхолдерам и пишет результат в `OUT_DIR`.

## Примеры

```bash
# 1) Шифрование (лучший вариант: только публичный ключ)
secretmd encrypt --in secrets.yaml --out secrets.enc.yaml --pub keys/key.public

# 2) Шифрование (если есть только приватный ключ; публичный берётся из него)
secretmd encrypt --in secrets.yaml --out secrets.enc.yaml --priv keys/key.private

# 3) Рендер документации в .rendered
secretmd render --docs docs --secrets secrets.enc.yaml --out .rendered --priv keys/key.private

# 4) Дешифрование в файл
secretmd decrypt --in secrets.enc.yaml --out secrets.dec.yaml --priv keys/key.private
```

## Компиляция secretmd

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o dist/secretmd-linux-amd64 ./cmd/secretmd

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -o dist/secretmd-darwin-arm64 ./cmd/secretmd

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o dist/secretmd-windows-amd64.exe ./cmd/secretmd
```

## Генерация ключей

Ключи можно сгенерировать следующим образом
```shell
openssl genrsa -out key.private 2048
openssl rsa -in key.private -outform PEM -pubout -out key.public
```

Рекомендуется использовать размерность не ниже 2048 ([рекомендация NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)).
Больше 2048 все же не стоит, т.к. буду слишком длинные секреты.
