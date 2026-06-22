package finding

import "fmt"

type Severity int

const (
	SevLow Severity = iota + 1
	SevMedium
	SevHigh
	SevCritical
)

var severityStr = map[Severity]string{
	SevLow:      "low",
	SevMedium:   "medium",
	SevHigh:     "high",
	SevCritical: "critical",
}

var severityValues = map[string]Severity{
	"low":      SevLow,
	"medium":   SevMedium,
	"high":     SevHigh,
	"critical": SevCritical,
}

func (s Severity) String() string {
	if v, ok := severityStr[s]; ok {
		return v
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

func (s Severity) MarshalJSON() ([]byte, error) {
	if s == 0 {
		return []byte("null"), nil
	}
	return jsonMarshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := jsonUnmarshal(data, &str); err != nil {
		return err
	}
	if str == "" || str == "null" {
		*s = 0
		return nil
	}
	v, ok := severityValues[str]
	if !ok {
		return fmt.Errorf("unknown severity: %s", str)
	}
	*s = v
	return nil
}

type Confidence int

const (
	ConfLow Confidence = iota + 1
	ConfMedium
	ConfHigh
)

var confidenceStr = map[Confidence]string{
	ConfLow:    "low",
	ConfMedium: "medium",
	ConfHigh:   "high",
}

var confidenceValues = map[string]Confidence{
	"low":    ConfLow,
	"medium": ConfMedium,
	"high":   ConfHigh,
}

func (c Confidence) String() string {
	if v, ok := confidenceStr[c]; ok {
		return v
	}
	return fmt.Sprintf("confidence(%d)", int(c))
}

func (c Confidence) MarshalJSON() ([]byte, error) {
	if c == 0 {
		return []byte("null"), nil
	}
	return jsonMarshal(c.String())
}

func (c *Confidence) UnmarshalJSON(data []byte) error {
	var str string
	if err := jsonUnmarshal(data, &str); err != nil {
		return err
	}
	if str == "" || str == "null" {
		*c = 0
		return nil
	}
	v, ok := confidenceValues[str]
	if !ok {
		return fmt.Errorf("unknown confidence: %s", str)
	}
	*c = v
	return nil
}

type SourceKind string

const (
	SourceFile       SourceKind = "file"
	SourceGit        SourceKind = "git"
	SourceGitHistory SourceKind = "git_history"
	SourceAgent      SourceKind = "agent"
	SourceDocker     SourceKind = "docker"
)

type Location struct {
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	CommitSHA string `json:"commit_sha,omitempty"`
}

type Evidence struct {
	Context string `json:"context,omitempty"`
}

type RemediationStep struct {
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
}

type Finding struct {
	ID          string            `json:"id"`
	Source      SourceKind        `json:"source"`
	DetectorID  string            `json:"detector_id"`
	SecretKind  string            `json:"secret_kind"`
	Severity    Severity          `json:"severity"`
	Confidence  Confidence        `json:"confidence"`
	Location    Location          `json:"location"`
	Preview     string            `json:"preview"`
	Fingerprint string            `json:"fingerprint"`
	Evidence    Evidence          `json:"evidence,omitempty"`
	Remediation []RemediationStep `json:"remediation,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
