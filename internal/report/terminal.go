package report

import (
	"fmt"
	"io"

	"github.com/huydt84/secret-guard/internal/finding"
)

func WriteTerminal(w io.Writer, findings []finding.Finding, showPreview, showFingerprints bool) {
	if len(findings) == 0 {
		_, _ = fmt.Fprintln(w, "No secrets found.")
		return
	}

	_, _ = fmt.Fprintf(w, "Found %d potential secret(s):\n\n", len(findings))
	for i, f := range findings {
		_, _ = fmt.Fprintf(w, "[%d] %s (%s)\n", i+1, f.SecretKind, f.Severity.String())
		_, _ = fmt.Fprintf(w, "    Detector: %s\n", f.DetectorID)
		_, _ = fmt.Fprintf(w, "    Confidence: %s\n", f.Confidence.String())
		_, _ = fmt.Fprintf(w, "    Location: %s:%d:%d\n", f.Location.Path, f.Location.Line, f.Location.Column)

		if showPreview && f.Preview != "" {
			_, _ = fmt.Fprintf(w, "    Preview: %s\n", f.Preview)
		}
		if showFingerprints && f.Fingerprint != "" {
			_, _ = fmt.Fprintf(w, "    Fingerprint: %s\n", f.Fingerprint)
		}
		if f.Evidence.Context != "" {
			_, _ = fmt.Fprintf(w, "    Context: %s\n", f.Evidence.Context)
		}
		_, _ = fmt.Fprintln(w)
	}
}
