package score_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	cvssv2 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v2"
	"go.zenithar.org/mitre/pkg/services/cvss/v2/score"
)

func TestScoreEvaluate(t *testing.T) {
	tcl := []struct {
		name           string
		vector         *cvssv2.Vector
		expectErr      bool
		expectedResult *cvssv2.Score
	}{
		{
			name:      "nil vector",
			expectErr: true,
		},
		{
			name:      "empty vector",
			vector:    &cvssv2.Vector{},
			expectErr: true,
		},
		{
			name: "valid vector",
			vector: &cvssv2.Vector{
				BaseMetrics: &cvssv2.BaseMetrics{
					AccessVector:          cvssv2.AccessVector_ACCESS_VECTOR_NETWORK,
					AccessComplexity:      cvssv2.AccessComplexity_ACCESS_COMPLEXITY_HIGH,
					Authentication:        cvssv2.Authentication_AUTHENTICATION_NONE,
					ConfidentialityImpact: cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_COMPLETE,
					IntegrityImpact:       cvssv2.IntegrityImpact_INTEGRITY_IMPACT_COMPLETE,
					AvailabilityImpact:    cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_COMPLETE,
				},
				TemporalMetrics: &cvssv2.TemporalMetrics{
					Exploitability:   cvssv2.Exploitability_EXPLOITABILITY_PROOF_OF_CONCEPT,
					RemediationLevel: cvssv2.RemediationLevel_REMEDIATION_LEVEL_WORKAROUND,
					ReportConfidence: cvssv2.ReportConfidence_REPORT_CONFIDENCE_UNCORROBORATED,
				},
				EnvironmentalMetrics: &cvssv2.EnvironmentalMetrics{
					CollateralDamagePotential:  cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_HIGH,
					TargetDistribution:         cvssv2.TargetDistribution_TARGET_DISTRIBUTION_HIGH,
					ConfidentialityRequirement: cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH,
					IntegrityRequirement:       cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH,
					AvailabilityRequirement:    cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH,
				},
			},
			expectErr: false,
			expectedResult: &cvssv2.Score{
				BaseScore: &cvssv2.BaseScore{
					Score:                 7.6,
					Impact:                10,
					FImpact:               1.176,
					Exploitability:        4.9,
					AccessVector:          1.0,
					AccessComplexity:      0.35,
					Authentication:        0.704,
					ConfidentialityImpact: 0.66,
					IntegrityImpact:       0.66,
					AvailabilityImpact:    0.66,
				},
				TemporalScore: &cvssv2.TemporalScore{
					Score: 6.2,
				},
				EnvironmentalScore: &cvssv2.EnvironmentalScore{
					CollateralDamagePotential:  0.5,
					TargetDistribution:         1.0,
					ConfidentialityRequirement: 1.51,
					IntegrityRequirement:       1.51,
					AvailabilityRequirement:    1.51,
					AdjustedImpact:             10,
					AdjustedBase:               7.6,
					AdjustedTemporal:           6.2,
					Score:                      8.1,
				},
			},
		},
		{
			name: "CVE-2003-0818 (AV:N/AC:L/Au:N/C:C/I:C/A:C)",
			vector: &cvssv2.Vector{
				BaseMetrics: &cvssv2.BaseMetrics{
					AccessVector:          cvssv2.AccessVector_ACCESS_VECTOR_NETWORK,
					AccessComplexity:      cvssv2.AccessComplexity_ACCESS_COMPLEXITY_LOW,
					Authentication:        cvssv2.Authentication_AUTHENTICATION_NONE,
					ConfidentialityImpact: cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_COMPLETE,
					IntegrityImpact:       cvssv2.IntegrityImpact_INTEGRITY_IMPACT_COMPLETE,
					AvailabilityImpact:    cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_COMPLETE,
				},
				TemporalMetrics: &cvssv2.TemporalMetrics{
					Exploitability:   cvssv2.Exploitability_EXPLOITABILITY_FUNCTIONAL,
					RemediationLevel: cvssv2.RemediationLevel_REMEDIATION_LEVEL_OFFICIAL_FIX,
					ReportConfidence: cvssv2.ReportConfidence_REPORT_CONFIDENCE_CONFIRMED,
				},
				EnvironmentalMetrics: &cvssv2.EnvironmentalMetrics{
					CollateralDamagePotential:  cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_HIGH,
					TargetDistribution:         cvssv2.TargetDistribution_TARGET_DISTRIBUTION_HIGH,
					ConfidentialityRequirement: cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_MEDIUM,
					IntegrityRequirement:       cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_MEDIUM,
					AvailabilityRequirement:    cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_MEDIUM,
				},
			},
			expectErr: false,
			expectedResult: &cvssv2.Score{
				BaseScore: &cvssv2.BaseScore{
					Score:                 10,
					Impact:                10,
					FImpact:               1.176,
					Exploitability:        10,
					AccessVector:          1.0,
					AccessComplexity:      0.71,
					Authentication:        0.704,
					ConfidentialityImpact: 0.66,
					IntegrityImpact:       0.66,
					AvailabilityImpact:    0.66,
				},
				TemporalScore: &cvssv2.TemporalScore{
					Score: 8.3,
				},
				EnvironmentalScore: &cvssv2.EnvironmentalScore{
					CollateralDamagePotential:  0.5,
					TargetDistribution:         1.0,
					ConfidentialityRequirement: 1.0,
					IntegrityRequirement:       1.0,
					AvailabilityRequirement:    1.0,
					AdjustedImpact:             10,
					AdjustedBase:               10,
					AdjustedTemporal:           8.3,
					Score:                      9.2,
				},
			},
		},
	}

	for _, tc := range tcl {
		t.Run(tc.name, func(t *testing.T) {
			result, err := score.Evaluate(tc.vector)
			if tc.expectErr && err == nil {
				t.Errorf("error expected, but got nil error")
			}
			if !cmp.Equal(tc.expectedResult, result) {
				t.Errorf("got %q, expected to equal %q", result, tc.expectedResult)
			}
		})
	}
}

func BenchmarkScoreEvaluate(b *testing.B) {
	v := &cvssv2.Vector{
		BaseMetrics: &cvssv2.BaseMetrics{
			AccessVector:          cvssv2.AccessVector_ACCESS_VECTOR_NETWORK,
			AccessComplexity:      cvssv2.AccessComplexity_ACCESS_COMPLEXITY_HIGH,
			Authentication:        cvssv2.Authentication_AUTHENTICATION_NONE,
			ConfidentialityImpact: cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_COMPLETE,
			IntegrityImpact:       cvssv2.IntegrityImpact_INTEGRITY_IMPACT_COMPLETE,
			AvailabilityImpact:    cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_COMPLETE,
		},
		TemporalMetrics: &cvssv2.TemporalMetrics{
			Exploitability:   cvssv2.Exploitability_EXPLOITABILITY_HIGH,
			RemediationLevel: cvssv2.RemediationLevel_REMEDIATION_LEVEL_UNAVAILABLE,
			ReportConfidence: cvssv2.ReportConfidence_REPORT_CONFIDENCE_CONFIRMED,
		},
		EnvironmentalMetrics: &cvssv2.EnvironmentalMetrics{
			CollateralDamagePotential:  cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_HIGH,
			TargetDistribution:         cvssv2.TargetDistribution_TARGET_DISTRIBUTION_HIGH,
			ConfidentialityRequirement: cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH,
			IntegrityRequirement:       cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH,
			AvailabilityRequirement:    cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH,
		},
	}

	for i := 0; i < b.N; i++ {
		score.Evaluate(v)
	}
}
