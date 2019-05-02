package score

import (
	cvssv3 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v3"
)

// Severity evaluate the given score and returns a severity level
func Severity(score float64) cvssv3.Severity {
	if score < 4.0 {
		return cvssv3.Severity_SEVERITY_LOW
	} else if score < 7.0 {
		return cvssv3.Severity_SEVERITY_MEDIUM
	} else if score < 9.0 {
		return cvssv3.Severity_SEVERITY_HIGH
	}
	return cvssv3.Severity_SEVERITY_CRITICAL
}
