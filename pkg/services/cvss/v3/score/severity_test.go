package score_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	cvssv3 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v3"
	"go.zenithar.org/mitre/pkg/services/cvss/v3/score"
)

func TestScoreSeverity(t *testing.T) {
	tcl := []struct {
		name           string
		score          float64
		expectedResult cvssv3.Severity
	}{
		{
			name:           "Low - 0.0",
			score:          0.0,
			expectedResult: cvssv3.Severity_SEVERITY_LOW,
		},
		{
			name:           "Low - 3.9",
			score:          3.9,
			expectedResult: cvssv3.Severity_SEVERITY_LOW,
		},
		{
			name:           "Medium - 4.0",
			score:          4.0,
			expectedResult: cvssv3.Severity_SEVERITY_MEDIUM,
		},
		{
			name:           "Medium - 6.9",
			score:          6.9,
			expectedResult: cvssv3.Severity_SEVERITY_MEDIUM,
		},
		{
			name:           "High - 8.9",
			score:          8.9,
			expectedResult: cvssv3.Severity_SEVERITY_HIGH,
		},
		{
			name:           "Critical - 9.0",
			score:          9.0,
			expectedResult: cvssv3.Severity_SEVERITY_CRITICAL,
		},
		{
			name:           "Critical - 10.0",
			score:          10.0,
			expectedResult: cvssv3.Severity_SEVERITY_CRITICAL,
		},
	}

	for _, tc := range tcl {
		t.Run(tc.name, func(t *testing.T) {
			result := score.Severity(tc.score)
			if !cmp.Equal(tc.expectedResult, result) {
				t.Errorf("got %q, expected to equal %q", result, tc.expectedResult)
			}
		})
	}
}
