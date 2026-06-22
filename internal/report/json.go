package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/huydinhtrong/secretguard/internal/finding"
)

func WriteJSON(w io.Writer, findings []finding.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		return fmt.Errorf("encode findings: %w", err)
	}
	return nil
}
