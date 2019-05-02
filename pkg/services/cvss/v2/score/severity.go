package score

import (
	cvssv2 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v2"
)

// Severity evaluate the given score and returns a severity level
func Severity(score float64) cvssv2.Severity {
	if score < 4.0 {
		return cvssv2.Severity_SEVERITY_LOW
	} else if score < 7.0 {
		return cvssv2.Severity_SEVERITY_MEDIUM
	}
	return cvssv2.Severity_SEVERITY_HIGH
}
