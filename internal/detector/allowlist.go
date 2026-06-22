package detector

import (
	"regexp"
	"strings"

	"github.com/huydinhtrong/secretguard/internal/finding"
)

type Allowlist struct {
	Patterns     []*regexp.Regexp
	Fingerprints []string
	Paths        []string
}

func NewAllowlist(paths, fingerprints, regexPatterns []string) (*Allowlist, error) {
	a := &Allowlist{
		Fingerprints: fingerprints,
		Paths:        paths,
	}
	for _, p := range regexPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		a.Patterns = append(a.Patterns, re)
	}
	return a, nil
}

func (a *Allowlist) IsAllowed(secret, path string) bool {
	fp := finding.GenerateFingerprint(secret)
	for _, allowed := range a.Fingerprints {
		if fp == allowed {
			return true
		}
	}
	for _, re := range a.Patterns {
		if re.MatchString(secret) {
			return true
		}
	}
	for _, p := range a.Paths {
		if matchPath(p, path) {
			return true
		}
	}
	return false
}

func matchPath(pattern, path string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix)
	}
	matched, _ := pathMatch(pattern, path)
	return matched
}

func pathMatch(pattern, name string) (bool, error) {
	parts := strings.Split(pattern, "/")
	nameParts := strings.Split(name, "/")

	pi := 0
	ni := 0
	for pi < len(parts) && ni < len(nameParts) {
		p := parts[pi]
		if p == "**" {
			if pi == len(parts)-1 {
				return true, nil
			}
			nextPart := parts[pi+1]
			for ni < len(nameParts) {
				if nameParts[ni] == nextPart || nextPart == "*" {
					break
				}
				ni++
			}
			pi++
			continue
		}
		if p == "*" || p == nameParts[ni] {
			pi++
			ni++
			continue
		}
		return false, nil
	}
	if ni < len(nameParts) {
		return false, nil
	}
	for pi < len(parts) {
		if parts[pi] != "**" {
			return false, nil
		}
		pi++
	}
	return true, nil
}
