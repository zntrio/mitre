package score_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	cvssv2 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v2"
	"go.zenithar.org/mitre/pkg/services/cvss/v2/score"
)

func TestScoreSeverity(t *testing.T) {
	tcl := []struct {
		name           string
		score          float64
		expectedResult cvssv2.Severity
	}{
		{
			name:           "Low - 0.0",
			score:          0.0,
			expectedResult: cvssv2.Severity_SEVERITY_LOW,
		},
		{
			name:           "Low - 3.9",
			score:          3.9,
			expectedResult: cvssv2.Severity_SEVERITY_LOW,
		},
		{
			name:           "Medium - 4.0",
			score:          4.0,
			expectedResult: cvssv2.Severity_SEVERITY_MEDIUM,
		},
		{
			name:           "Medium - 6.9",
			score:          6.9,
			expectedResult: cvssv2.Severity_SEVERITY_MEDIUM,
		},
		{
			name:           "High - 7.0",
			score:          7.0,
			expectedResult: cvssv2.Severity_SEVERITY_HIGH,
		},
		{
			name:           "High - 10.0",
			score:          10.0,
			expectedResult: cvssv2.Severity_SEVERITY_HIGH,
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
