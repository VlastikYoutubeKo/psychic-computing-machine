#!/usr/bin/env bash
# Proves the PHP admin's secret_box.php and the Go gateway's secretbox
# package agree on the exact same ciphertext wire format in both
# directions. A silent mismatch here would only surface in production as
# "Tvheadend auth mysteriously fails" -- worth a real check.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

KEY_B64=$(php -r 'echo base64_encode(random_bytes(32));')
PLAINTEXT='tvheadend-p@ssw0rd!'

echo "== PHP encrypts, Go decrypts =="
PHP_CIPHERTEXT=$(php -r "
require '$ROOT/admin/includes/secret_box.php';
echo sv_encrypt(base64_decode('$KEY_B64'), '$PLAINTEXT');
")

cat > "$WORK/decrypt_check.go" <<'EOF'
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"streamvault/gateway/internal/secretbox"
)

func main() {
	keyB64 := os.Args[1]
	ciphertext := os.Args[2]
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		panic(err)
	}
	plain, err := secretbox.Decrypt(key, ciphertext)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	fmt.Print(string(plain))
}
EOF
mkdir -p "$ROOT/gateway/cmd/_crypto_interop_check"
cp "$WORK/decrypt_check.go" "$ROOT/gateway/cmd/_crypto_interop_check/main.go"
GOT=$(cd "$ROOT/gateway" && go run ./cmd/_crypto_interop_check "$KEY_B64" "$PHP_CIPHERTEXT")
rm -rf "$ROOT/gateway/cmd/_crypto_interop_check"

if [ "$GOT" = "$PLAINTEXT" ]; then
  echo "PASS: Go decrypted what PHP encrypted"
else
  echo "FAIL: Go got '$GOT', expected '$PLAINTEXT'"
  exit 1
fi

echo "== Go encrypts, PHP decrypts =="
cat > "$WORK/encrypt_check.go" <<'EOF'
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"streamvault/gateway/internal/secretbox"
)

func main() {
	keyB64 := os.Args[1]
	plaintext := os.Args[2]
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		panic(err)
	}
	enc, err := secretbox.Encrypt(key, []byte(plaintext))
	if err != nil {
		panic(err)
	}
	fmt.Print(enc)
}
EOF
mkdir -p "$ROOT/gateway/cmd/_crypto_interop_check2"
cp "$WORK/encrypt_check.go" "$ROOT/gateway/cmd/_crypto_interop_check2/main.go"
GO_CIPHERTEXT=$(cd "$ROOT/gateway" && go run ./cmd/_crypto_interop_check2 "$KEY_B64" "$PLAINTEXT")
rm -rf "$ROOT/gateway/cmd/_crypto_interop_check2"

PHP_GOT=$(php -r "
require '$ROOT/admin/includes/secret_box.php';
echo sv_decrypt(base64_decode('$KEY_B64'), '$GO_CIPHERTEXT');
")
if [ "$PHP_GOT" = "$PLAINTEXT" ]; then
  echo "PASS: PHP decrypted what Go encrypted"
else
  echo "FAIL: PHP got '$PHP_GOT', expected '$PLAINTEXT'"
  exit 1
fi

echo "ALL CRYPTO INTEROP CHECKS PASSED"
