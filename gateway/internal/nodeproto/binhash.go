package nodeproto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

var (
	exeHashOnce sync.Once
	exeHash     string
	exeHashErr  error
)

// ExecutableSHA256 is the hex SHA-256 of the running executable. The control
// gateway publishes it so nodes can tell when their binary is outdated, and
// nodes report it in their heartbeat. Computed once: a running process's
// binary doesn't change (an upgrade restarts the process).
func ExecutableSHA256() (string, error) {
	exeHashOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			exeHashErr = err
			return
		}
		f, err := os.Open(exe)
		if err != nil {
			exeHashErr = err
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			exeHashErr = err
			return
		}
		exeHash = hex.EncodeToString(h.Sum(nil))
	})
	return exeHash, exeHashErr
}
