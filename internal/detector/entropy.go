package detector

import (
	"math"
	"regexp"
)

var tokenRe = regexp.MustCompile(`[A-Za-z0-9_-]{16,}`)

func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, c := range s {
		counts[c]++
	}
	var entropy float64
	l := float64(len(s))
	for _, count := range counts {
		p := float64(count) / l
		entropy -= p * math.Log2(p)
	}
	return entropy
}

const minEntropyThreshold = 4.0

func findHighEntropyTokens(content string) []matchResult {
	var results []matchResult
	matches := tokenRe.FindAllStringIndex(content, -1)
	for _, m := range matches {
		token := content[m[0]:m[1]]
		entropy := ShannonEntropy(token)
		if entropy >= minEntropyThreshold {
			lineNum, colNum := positionFromOffset(content, m[0])
			results = append(results, matchResult{
				value:  token,
				line:   lineNum,
				column: colNum,
				offset: m[0],
			})
		}
	}
	return results
}
