package finding

import (
	"encoding/json"
	"testing"
)

func TestGenerateFingerprint_SameSecret(t *testing.T) {
	s := "sk-test_abcdefghijklmnopqrstuvwxyz123456"
	f1 := GenerateFingerprint(s)
	f2 := GenerateFingerprint(s)
	if f1 != f2 {
		t.Errorf("same secret produced different fingerprints: %s vs %s", f1, f2)
	}
}

func TestGenerateFingerprint_DifferentSecrets(t *testing.T) {
	s1 := "sk-test_abcdefghijklmnopqrstuvwxyz123456"
	s2 := "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	f1 := GenerateFingerprint(s1)
	f2 := GenerateFingerprint(s2)
	if f1 == f2 {
		t.Errorf("different secrets produced same fingerprint: %s", f1)
	}
}

func TestGenerateFingerprint_Format(t *testing.T) {
	s := "sk-test_abcdefghijklmnopqrstuvwxyz123456"
	fp := GenerateFingerprint(s)
	if len(fp) != 19 { // "sha256:" + 12 hex chars = 7 + 12
		t.Errorf("unexpected fingerprint length %d: %s", len(fp), fp)
	}
	if fp[:7] != "sha256:" {
		t.Errorf("fingerprint missing sha256: prefix: %s", fp)
	}
}

func TestMaskPreview_ShortSecret(t *testing.T) {
	v := MaskPreview("short")
	if v != "***" {
		t.Errorf("expected ***, got %s", v)
	}
}

func TestMaskPreview_LongSecret(t *testing.T) {
	s := "sk-test_abcdefghijklmnopqrstuvwxyz123456"
	v := MaskPreview(s)
	if v == s {
		t.Errorf("preview should not equal full secret")
	}
	if len(v) >= len(s) {
		t.Errorf("preview should be shorter than secret")
	}
	if v[:4] != s[:4] {
		t.Errorf("preview should start with first 4 chars: got %s, expected start %s", v, s[:4])
	}
	if v[len(v)-4:] != s[len(s)-4:] {
		t.Errorf("preview should end with last 4 chars: got %s, expected end %s", v[len(v)-4:], s[len(s)-4:])
	}
}

func TestMaskPreview_ContainsEllipsis(t *testing.T) {
	s := "sk-test_abcdefghijklmnopqrstuvwxyz123456"
	v := MaskPreview(s)
	if len(v) != 11 { // 4 + "..." + 4 = 11
		t.Errorf("expected preview length 11, got %d: %s", len(v), v)
	}
}

func TestSeverity_String(t *testing.T) {
	cases := []struct {
		s    Severity
		want string
	}{
		{SevLow, "low"},
		{SevMedium, "medium"},
		{SevHigh, "high"},
		{SevCritical, "critical"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %s, want %s", tc.s, got, tc.want)
		}
	}
}

func TestConfidence_String(t *testing.T) {
	cases := []struct {
		c    Confidence
		want string
	}{
		{ConfLow, "low"},
		{ConfMedium, "medium"},
		{ConfHigh, "high"},
	}
	for _, tc := range cases {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("Confidence(%d).String() = %s, want %s", tc.c, got, tc.want)
		}
	}
}

func TestSeverity_JSON(t *testing.T) {
	f := Finding{Severity: SevHigh}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Severity != SevHigh {
		t.Errorf("expected SevHigh, got %v", decoded.Severity)
	}
}

func TestConfidence_JSON(t *testing.T) {
	f := Finding{Confidence: ConfHigh}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Confidence != ConfHigh {
		t.Errorf("expected ConfHigh, got %v", decoded.Confidence)
	}
}
