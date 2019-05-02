package score

import (
	cvssv2 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v2"
)

// Evaluate returns the evaluated score of the given vector object
func Evaluate(v *cvssv2.Vector) (*cvssv2.Score, error) {
	return nil, nil
}
