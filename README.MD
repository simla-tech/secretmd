# secretmd

secretmd — утилита для шифрования секретов в Markdown файлах.

---

## Содержание

- [Криптосхема (как устроено шифрование)](#криптосхема-как-устроено-шифрование)
- [Плейсхолдеры в Markdown](#плейсхолдеры-в-markdown)
- [Шифрование внешних файлов](#шифрование-внешних-файлов)
- [Команды](#команды)
    - [Encrypt](#encrypt)
    - [Decrypt](#decrypt)
- [Примеры](#примеры)
- [Компиляция secretmd](#компиляция-secretmd)
- [Генерация ключей](#генерация-ключей)

---

## Криптосхема (как устроено шифрование)

Каждый секрет шифруется случайным симметричным AES-256 ключом, который в свою очередь
зашифровывается переданным RSA ключом. Такой подход позволяет шифровать секреты произвольный длины.

Зашифрованные секреты хранятся в виде `base64url` от JSON-конверта (envelope). Внутри конверта
содержатся поля:

- **`ek`** — `RSA-OAEP-SHA256(pub, dataKey)` *(encrypted key / обёртка симметричного ключа)*
- **`nonce`** — одноразовое значение (*nonce*) для **AES-GCM**
- **`ct`** — результат `AES-256-GCM(ciphertext||tag)` *(ciphertext вместе с authentication tag)*

---

## Плейсхолдеры в Markdown

Для plaintext секрета используется маркер:

```md
!encrypt{MY_SECRET}
```

Для зашифрованного секрета используется маркер:

```md
!secret{<TOKEN>}
```

---

## Шифрование внешних файлов

Иногда, вместо хранения секрета прямо в markdown файле, удобно хранить его во внешнем файле и
ссылаться на него из документации.

В этом случае, можно добавить к имени файла суффикс `.encrypt`, и использовать флаг
`--encrypt-external-files` при вызове команды `encrypt` (см. ниже).

Содержимое файла будет заменено на зашифрованный токен, а суффикс `.encrypt` будет заменен на
`.secret`. При шифровании меняется именно содержимое файла, а не создается копия.

---

## Команды

### Encrypt

```bash
secretmd encrypt --root <DIR> (--pub <PUBLIC_PEM> | --priv <PRIVATE_PEM>) [--encrypt-external-files]
```

Рекурсивно проходит по `*.md` файлам в `<DIR>`, находит `!encrypt{...}` и заменяет на
`!secret{...}`. Перезаписывает файлы на месте.

Если указан флаг `--encrypt-external-files`, то также ищет файлы с суффиксом
`.encrypt`, шифрует их содержимое и сохраняет файлы с суффиксом `.secret`.

### Decrypt

```bash
secretmd decrypt --file <PATH> --priv <PRIVATE_PEM> [--export-dir <OUT_DIR>]
```

Выводит расшифрованное содержимое файла в stdout. Для `*.md` файлов будут дешифрованы все
`!secret{...}`. Для `*.secret` файлов будет расшифровано всё содержимое.

Для `*.secret` файлов можно указать флаг `--export-dir <OUT_DIR>`, в этом случае
расшифрованные файлы будут сохранены в указанную директорию с оригинальным именем
(без суффикса `.secret`).

---

## Примеры

```bash
# 1) Шифрование
secretmd encrypt --root docs --pub keys/public.pem

# 2) Шифрование (если есть только приватный ключ; публичный берётся из него)
secretmd encrypt --root docs --priv keys/key.private

# 3) Шифрование (если нужно зашифровать внешние файлы с суффиксом .encrypt)
secretmd encrypt --root docs --pub keys/public.pem --encrypt-external-files

# 4) Дешифрование и вывод файла в stdout
secretmd decrypt --file docs/setup.md --priv keys/private.pem
secretmd decrypt --file docs/config.secret --priv keys/private.pem

# 5) Дешифрование и экспорт в указанную директорию
secretmd decrypt --file docs/config.secret --priv keys/private.pem --export-dir decrypted_configs
```

---

## Компиляция secretmd

Для компиляции проекта требуется установка GO (https://go.dev/doc/install).

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o dist/secretmd-linux-amd64 ./cmd/secretmd

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -o dist/secretmd-darwin-arm64 ./cmd/secretmd

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o dist/secretmd-windows-amd64.exe ./cmd/secretmd
```

Уже скомпилированные бинарники есть в папке dist.

---

## Генерация ключей

Ключи можно сгенерировать следующим образом

```shell
openssl genrsa -out key.private 2048
openssl rsa -in key.private -outform PEM -pubout -out key.public
```

Рекомендуется использовать размерность не ниже
2048 ([рекомендация NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)).
Больше 2048 все же не стоит, т.к. буду слишком длинные секреты.
