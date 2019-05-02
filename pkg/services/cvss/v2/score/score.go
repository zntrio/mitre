package score

import (
	cvssv2 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v2"
	"golang.org/x/xerrors"
)

// Evaluate returns the evaluated score of the given vector object
func Evaluate(v *cvssv2.Vector) (*cvssv2.Score, error) {

	if v == nil {
		return nil, xerrors.New("score: unable to evaluate nil vector")
	}
	if v.BaseMetrics == nil {
		return nil, xerrors.New("score: unable to evaluate invalid vector, missing base metrics")
	}

	// Calculate intermediary values
	impact := impactScore(v.BaseMetrics)
	baseScore := baseScore(v.BaseMetrics)

	res := &cvssv2.Score{
		BaseScore: &cvssv2.BaseScore{
			AccessVector:          weightAccessVector(v.BaseMetrics.AccessVector),
			AccessComplexity:      weightAccessComplexity(v.BaseMetrics.AccessComplexity),
			Authentication:        weightAuthentication(v.BaseMetrics.Authentication),
			ConfidentialityImpact: weightConfImpact(v.BaseMetrics.ConfidentialityImpact),
			IntegrityImpact:       weightIntegImpact(v.BaseMetrics.IntegrityImpact),
			AvailabilityImpact:    weightAvailImpact(v.BaseMetrics.AvailabilityImpact),
			Impact:                impact,
			FImpact:               fimpactScore(impact),
			Exploitability:        exploitabilityScore(v.BaseMetrics),
			Score:                 baseScore,
		},
	}

	if v.TemporalMetrics != nil {
		res.TemporalScore = &cvssv2.TemporalScore{
			Score: temporalScore(baseScore, v.TemporalMetrics),
		}

		if v.EnvironmentalMetrics != nil {
			res.EnvironmentalScore = &cvssv2.EnvironmentalScore{
				CollateralDamagePotential:  weightCollateralDamagePotential(v.EnvironmentalMetrics.CollateralDamagePotential),
				TargetDistribution:         weightTargetDistribution(v.EnvironmentalMetrics.TargetDistribution),
				ConfidentialityRequirement: weightSecurityRequirement(v.EnvironmentalMetrics.ConfidentialityRequirement),
				IntegrityRequirement:       weightSecurityRequirement(v.EnvironmentalMetrics.IntegrityRequirement),
				AvailabilityRequirement:    weightSecurityRequirement(v.EnvironmentalMetrics.AvailabilityRequirement),
				AdjustedImpact:             adjustedImpact(v.BaseMetrics, v.EnvironmentalMetrics),
				AdjustedTemporal:           adjustedTemporal(v),
				AdjustedBase:               adjustedBase(v),
				Score:                      environmentalScore(v),
			}
		}
	}

	// Return result
	return res, nil
}
