package finding

import (
	"crypto/sha256"
	"fmt"
)

func GenerateFingerprint(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("sha256:%x", h[:6])
}
