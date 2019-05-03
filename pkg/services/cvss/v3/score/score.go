package score

import (
	cvssv3 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v3"
	"golang.org/x/xerrors"
)

// Evaluate returns the evaluated score of the given vector object
func Evaluate(v *cvssv3.Vector) (*cvssv3.Score, error) {

	if v == nil {
		return nil, xerrors.New("score: unable to evaluate nil vector")
	}
	if v.BaseMetrics == nil {
		return nil, xerrors.New("score: unable to evaluate invalid vector, missing base metrics")
	}

	res := &cvssv3.Score{
		BaseScore: &cvssv3.BaseScore{
			AttackVector:          weightAttackVector(v.BaseMetrics.AttackVector),
			AttackComplexity:      weightAttackComplexity(v.BaseMetrics.AttackComplexity),
			PrivilegeRequired:     weightPrivilegeRequired(v.BaseMetrics.PrivilegeRequired, v.BaseMetrics.Scope),
			UserInteraction:       weightUserInteraction(v.BaseMetrics.UserInteraction),
			ConfidentialityImpact: weightConfidentiality(v.BaseMetrics.ConfidentialityImpact),
			IntegrityImpact:       weightIntegrity(v.BaseMetrics.IntegrityImpact),
			AvailabilityImpact:    weightAvailability(v.BaseMetrics.AvailabilityImpact),
			Impact:                roundUp1(impactScore(v.BaseMetrics)),
			Exploitability:        roundUp1(exploitabilityScore(v.BaseMetrics)),
			Score:                 baseScore(v),
		},
	}

	// Return result
	return res, nil
}
