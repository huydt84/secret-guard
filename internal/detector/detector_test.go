package detector

import (
	"strings"
	"testing"

	"github.com/huydt84/secret-guard/internal/finding"
)

func TestBuiltinRules_OpenAI(t *testing.T) {
	content := []byte(`OPENAI_API_KEY="sk-test_abcdefghijklmnopqrstuvwxyz123456"`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	if len(findings) == 0 {
		t.Fatal("expected OpenAI key detection")
	}
	matched := false
	for _, f := range findings {
		if f.DetectorID == "openai-api-key" {
			matched = true
			if f.Preview == "" || strings.Contains(f.Preview, "sk-test_abcdefghijklmnopqrstuvwxyz123456") {
				t.Errorf("preview leaked full secret: %s", f.Preview)
			}
			break
		}
	}
	if !matched {
		t.Error("openai-api-key rule did not fire")
	}
}

func TestBuiltinRules_Anthropic(t *testing.T) {
	content := []byte(`ANTHROPIC_API_KEY="sk-ant-test_abcdefghijklmnopqrstuvwxyz123456"`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	found := false
	for _, f := range findings {
		if f.DetectorID == "anthropic-api-key" {
			found = true
			break
		}
	}
	if !found {
		t.Error("anthropic-api-key rule did not fire")
	}
}

func TestBuiltinRules_AWSAccessKey(t *testing.T) {
	content := []byte(`AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	found := false
	for _, f := range findings {
		if f.DetectorID == "aws-access-key-id" {
			found = true
			break
		}
	}
	if !found {
		t.Error("aws-access-key-id rule did not fire")
	}
}

func TestBuiltinRules_AWSSecretKey(t *testing.T) {
	content := []byte(`AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	found := false
	for _, f := range findings {
		if f.DetectorID == "aws-secret-key" {
			found = true
			if f.Confidence != finding.ConfHigh {
				t.Errorf("expected high confidence with keyword, got %v", f.Confidence)
			}
			break
		}
	}
	if !found {
		t.Error("aws-secret-key rule did not fire (keyword nearby)")
	}
}

func TestBuiltinRules_AWSSecretKey_NoKeyword(t *testing.T) {
	content := []byte(`somevar=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.txt", content)
	for _, f := range findings {
		if f.DetectorID == "aws-secret-key" {
			t.Error("aws-secret-key should NOT fire without keyword context")
		}
	}
}

func TestBuiltinRules_GitHubToken(t *testing.T) {
	content := []byte(`GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	found := false
	for _, f := range findings {
		if f.DetectorID == "github-token" {
			found = true
			break
		}
	}
	if !found {
		t.Error("github-token rule did not fire")
	}
}

func TestBuiltinRules_NPMToken(t *testing.T) {
	content := []byte(`NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz123456`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	found := false
	for _, f := range findings {
		if f.DetectorID == "npm-token" {
			found = true
			break
		}
	}
	if !found {
		t.Error("npm-token rule did not fire")
	}
}

func TestBuiltinRules_PrivateKey(t *testing.T) {
	content := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCq...
-----END RSA PRIVATE KEY-----`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "key.pem", content)
	found := false
	for _, f := range findings {
		if f.DetectorID == "private-key" {
			found = true
			break
		}
	}
	if !found {
		t.Error("private-key rule did not fire")
	}
}

func TestBuiltinRules_DatabaseURL(t *testing.T) {
	content := []byte(`DATABASE_URL=postgres://user:supersecretpassword@localhost:5432/app`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	found := false
	for _, f := range findings {
		if f.DetectorID == "database-url" {
			found = true
			break
		}
	}
	if !found {
		t.Error("database-url rule did not fire")
	}
}

func TestEntropyDetector(t *testing.T) {
	content := []byte(`token=aB3dE5fGhIjKlMnOpQrStUvWxYz1234567890`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.txt", content)
	found := false
	for _, f := range findings {
		if f.DetectorID == "high-entropy" {
			found = true
			break
		}
	}
	if !found {
		t.Error("high-entropy detector did not fire on long random token")
	}
}

func TestAllowlist_Fingerprint(t *testing.T) {
	secret := "sk-test_abcdefghijklmnopqrstuvwxyz123456"
	fp := finding.GenerateFingerprint(secret)
	a, err := NewAllowlist(nil, []string{fp}, nil)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`OPENAI_API_KEY="` + secret + `"`)
	d := New(BuiltinRules, a)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	for _, f := range findings {
		if f.DetectorID == "openai-api-key" {
			t.Error("openai-api-key should be suppressed by fingerprint allowlist")
		}
	}
}

func TestAllowlist_Regex(t *testing.T) {
	a, err := NewAllowlist(nil, nil, []string{"sk-test_"})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`OPENAI_API_KEY="sk-test_abcdefghijklmnopqrstuvwxyz123456"`)
	d := New(BuiltinRules, a)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	for _, f := range findings {
		if f.DetectorID == "openai-api-key" {
			t.Error("openai-api-key should be suppressed by regex allowlist")
		}
	}
}

func TestAllowlist_Path(t *testing.T) {
	a, err := NewAllowlist([]string{"testdata/**"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`OPENAI_API_KEY="sk-test_abcdefghijklmnopqrstuvwxyz123456"`)
	d := New(BuiltinRules, a)
	findings := d.DetectAll(finding.SourceFile, "testdata/secrets/env.txt", content)
	for _, f := range findings {
		if f.DetectorID == "openai-api-key" {
			t.Error("findings under testdata/ should be suppressed")
		}
	}
}

func TestAllowlist_PathNoMatch(t *testing.T) {
	a, err := NewAllowlist([]string{"testdata/**"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`OPENAI_API_KEY="sk-test_abcdefghijklmnopqrstuvwxyz123456"`)
	d := New(BuiltinRules, a)
	findings := d.DetectAll(finding.SourceFile, "config/prod.env", content)
	found := false
	for _, f := range findings {
		if f.DetectorID == "openai-api-key" {
			found = true
			break
		}
	}
	if !found {
		t.Error("findings outside testdata/ should not be suppressed")
	}
}

func TestShannonEntropy(t *testing.T) {
	low := ShannonEntropy("aaaaaaaaaaaaaaaa")
	high := ShannonEntropy("aB3dE5fGhIjKlMnOpQrStUvWxYz1234567890")
	if low >= high {
		t.Errorf("expected low entropy < high entropy: %f >= %f", low, high)
	}
}

func TestShannonEntropy_Empty(t *testing.T) {
	if e := ShannonEntropy(""); e != 0 {
		t.Errorf("expected 0 entropy for empty string, got %f", e)
	}
}

func TestShannonEntropy_Threshold(t *testing.T) {
	high := ShannonEntropy("aB3dE5fGhIjKlMnOpQrStUvWxYz1234567890")
	if high < minEntropyThreshold {
		t.Errorf("expected entropy >= %f for random token, got %f", minEntropyThreshold, high)
	}
}

func TestContainsKeyword(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`OPENAI_API_KEY="sk-test..."`, true},
		{`password=supersecret`, true},
		{`const x = 42;`, false},
		{`// just a comment`, false},
	}
	for _, tc := range cases {
		got := containsKeyword(tc.line)
		if got != tc.want {
			t.Errorf("containsKeyword(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestPositionFromOffset(t *testing.T) {
	text := "line1\nline2\nline3"
	line, col := positionFromOffset(text, 0)
	if line != 1 || col != 1 {
		t.Errorf("offset 0: expected (1,1), got (%d,%d)", line, col)
	}
	line, col = positionFromOffset(text, 6)
	if line != 2 || col != 1 {
		t.Errorf("offset 6: expected (2,1), got (%d,%d)", line, col)
	}
	line, col = positionFromOffset(text, 7)
	if line != 2 || col != 2 {
		t.Errorf("offset 7: expected (2,2), got (%d,%d)", line, col)
	}
}

func TestFingerprint_SameAcrossCalls(t *testing.T) {
	// Same secret always produces same fingerprint (already tested)
	// Also test that the detector produces consistent fingerprints
	content := []byte(`OPENAI_API_KEY="sk-test_abcdefghijklmnopqrstuvwxyz123456"`)
	d := New(BuiltinRules, nil)
	f1 := d.DetectAll(finding.SourceFile, "test.env", content)
	f2 := d.DetectAll(finding.SourceFile, "test.env", content)
	if len(f1) == 0 || len(f2) == 0 {
		t.Fatal("expected findings")
	}
	for i := range f1 {
		if i >= len(f2) {
			break
		}
		if f1[i].Fingerprint != f2[i].Fingerprint {
			t.Errorf("same secret produced different fingerprints: %s vs %s", f1[i].Fingerprint, f2[i].Fingerprint)
		}
	}
}

func TestPreview_NoSecretLeak(t *testing.T) {
	content := []byte(`OPENAI_API_KEY="sk-test_abcdefghijklmnopqrstuvwxyz123456"`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	for _, f := range findings {
		if strings.Contains(f.Preview, "sk-test_") && f.Preview != "sk-t...3456" {
			t.Errorf("preview may contain secret: %s", f.Preview)
		}
	}
}

func TestFindHighEntropyTokens(t *testing.T) {
	content := "token=aB3dE5fGhIjKlMnOpQrStUvWxYz1234567890"
	results := findHighEntropyTokens(content)
	if len(results) == 0 {
		t.Error("expected at least one high-entropy token")
	}
	for _, r := range results {
		if r.value == "" {
			t.Error("found empty token")
		}
	}
}

func TestDetectAll_SourceKind(t *testing.T) {
	content := []byte(`OPENAI_API_KEY="sk-test_abcdefghijklmnopqrstuvwxyz123456"`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceGit, "test.env", content)
	for _, f := range findings {
		if f.Source != finding.SourceGit {
			t.Errorf("expected SourceGit, got %v", f.Source)
		}
	}
}

func TestDetectAll_DedupEntropy(t *testing.T) {
	// OpenAI key matched by regex rule should NOT also fire entropy detector
	content := []byte(`OPENAI_API_KEY="sk-test_abcdefghijklmnopqrstuvwxyz123456"`)
	d := New(BuiltinRules, nil)
	findings := d.DetectAll(finding.SourceFile, "test.env", content)
	highEntropyCount := 0
	for _, f := range findings {
		if f.DetectorID == "high-entropy" {
			highEntropyCount++
		}
	}
	if highEntropyCount > 0 {
		t.Errorf("high-entropy should not fire for already-detected secrets, got %d entropy findings", highEntropyCount)
	}
}

func TestNewAllowlist_InvalidRegex(t *testing.T) {
	_, err := NewAllowlist(nil, nil, []string{"[invalid"})
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

func TestAdjustConfidenceByContext(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		line string
		want finding.Confidence
	}{
		{
			name: "aws-secret with keyword",
			rule: Rule{RequireKeyword: true, Confidence: finding.ConfMedium},
			line: `AWS_SECRET_ACCESS_KEY=supersecret`,
			want: finding.ConfHigh,
		},
		{
			name: "aws-secret without keyword",
			rule: Rule{RequireKeyword: true, Confidence: finding.ConfMedium},
			line: `foo=bar`,
			want: finding.ConfLow,
		},
		{
			name: "normal rule with keyword",
			rule: Rule{RequireKeyword: false, Confidence: finding.ConfHigh},
			line: `OPENAI_API_KEY="sk-test..."`,
			want: finding.ConfHigh,
		},
		{
			name: "normal rule without keyword",
			rule: Rule{RequireKeyword: false, Confidence: finding.ConfHigh},
			line: `const x = "sk-test..."`,
			want: finding.ConfMedium,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := adjustConfidenceByContext(tc.rule, tc.line)
			if got != tc.want {
				t.Errorf("adjustConfidenceByContext = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuiltinRules_AllDetectExpectedSecrets(t *testing.T) {
	tests := []struct {
		name       string
		detectorID string
		content    string
	}{
		{"OpenAI", "openai-api-key", `x="sk-test_abcdefghijklmnopqrstuvwxyz123456"`},
		{"Anthropic", "anthropic-api-key", `x="sk-ant-test_abcdefghijklmnopqrstuvwxyz123456"`},
		{"AWSAccessKey", "aws-access-key-id", `x=AKIAIOSFODNN7EXAMPLE`},
		{"AWSSecretKey", "aws-secret-key", `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`},
		{"GitHub", "github-token", `x=ghp_abcdefghijklmnopqrstuvwxyz1234567890`},
		{"npm", "npm-token", `x=npm_abcdefghijklmnopqrstuvwxyz123456`},
		{"PrivateKey", "private-key", `-----BEGIN EC PRIVATE KEY-----`},
		{"DatabaseURL", "database-url", `x=postgres://user:supersecretpassword@localhost:5432/app`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := New(BuiltinRules, nil)
			findings := d.DetectAll(finding.SourceFile, "test.env", []byte(tc.content))
			for _, f := range findings {
				if f.DetectorID == tc.detectorID {
					return
				}
			}
			t.Errorf("rule %s did not detect expected secret", tc.detectorID)
		})
	}
}

func TestPathMatch(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"exact", "a/b/c", "a/b/c", true},
		{"exact no match", "a/b/c", "a/b/d", false},
		{"star single", "a/*/c", "a/x/c", true},
		{"star no match", "a/*/c", "a/x/y/c", false},
		{"globstar suffix", "a/**", "a/b/c", true},
		{"globstar suffix direct", "a/**", "a", true},
		{"globstar mid", "a/**/b", "a/x/b", true},
		{"globstar mid multi", "a/**/b", "a/x/y/b", true},
		{"globstar mid direct", "a/**/b", "a/b", true},
		{"globstar mid no match", "a/**/b", "a/x/y/c", false},
		{"star segment", "a/*/c", "a/b/c", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := pathMatch(tc.pattern, tc.path)
			if got != tc.want {
				t.Errorf("pathMatch(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
			}
		})
	}
}

func TestAllowlist_PathMidGlob(t *testing.T) {
	a, err := NewAllowlist([]string{"a/**/b"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsAllowed("secret", "a/x/b") {
		t.Error("a/**/b should allow a/x/b")
	}
	if a.IsAllowed("secret", "a/x/y/c") {
		t.Error("a/**/b should NOT allow a/x/y/c")
	}
}

func TestMaskSecretInLine(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		secret string
		want   string
	}{
		{"contains secret", `key="sk-test_abc"`, "sk-test_abc", `key="[REDACTED]"`},
		{"no secret", `key=value`, "secret", `key=value`},
		{"empty secret", `key=value`, "", `key=value`},
		{"multiple occurrences", `a=xyz b=xyz`, "xyz", "a=[REDACTED] b=[REDACTED]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := maskSecretInLine(tc.line, tc.secret)
			if got != tc.want {
				t.Errorf("maskSecretInLine(%q, %q) = %q, want %q", tc.line, tc.secret, got, tc.want)
			}
		})
	}
}
