package vector_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	cvssv2 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v2"
	"go.zenithar.org/mitre/pkg/services/cvss/v2/vector"
)

func TestVectorToString(t *testing.T) {
	tcl := []struct {
		name           string
		vector         *cvssv2.Vector
		expectedResult string
		expectedErr    bool
	}{
		{
			name:           "nil vector",
			vector:         nil,
			expectedErr:    true,
			expectedResult: "",
		},
		{
			name:           "empty vector",
			vector:         &cvssv2.Vector{},
			expectedErr:    true,
			expectedResult: "",
		},
		{
			name: "empty sub metrics",
			vector: &cvssv2.Vector{
				BaseMetrics:          &cvssv2.BaseMetrics{},
				EnvironmentalMetrics: &cvssv2.EnvironmentalMetrics{},
				TemporalMetrics:      &cvssv2.TemporalMetrics{},
			},
			expectedResult: "AV:ND/AC:ND/Au:ND/C:ND/I:ND/A:ND/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND",
		},
		{
			name: "valid full vector",
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
			},
			expectedResult: "AV:N/AC:H/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H",
		},
		{
			name: "valid partial vector with base only",
			vector: &cvssv2.Vector{
				BaseMetrics: &cvssv2.BaseMetrics{
					AccessVector:          cvssv2.AccessVector_ACCESS_VECTOR_NETWORK,
					AccessComplexity:      cvssv2.AccessComplexity_ACCESS_COMPLEXITY_HIGH,
					Authentication:        cvssv2.Authentication_AUTHENTICATION_NONE,
					ConfidentialityImpact: cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_COMPLETE,
					IntegrityImpact:       cvssv2.IntegrityImpact_INTEGRITY_IMPACT_COMPLETE,
					AvailabilityImpact:    cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_COMPLETE,
				},
			},
			expectedResult: "AV:N/AC:H/Au:N/C:C/I:C/A:C",
		},
		{
			name: "valid partial vector without temporal",
			vector: &cvssv2.Vector{
				BaseMetrics: &cvssv2.BaseMetrics{
					AccessVector:          cvssv2.AccessVector_ACCESS_VECTOR_NETWORK,
					AccessComplexity:      cvssv2.AccessComplexity_ACCESS_COMPLEXITY_HIGH,
					Authentication:        cvssv2.Authentication_AUTHENTICATION_NONE,
					ConfidentialityImpact: cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_COMPLETE,
					IntegrityImpact:       cvssv2.IntegrityImpact_INTEGRITY_IMPACT_COMPLETE,
					AvailabilityImpact:    cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_COMPLETE,
				},
				EnvironmentalMetrics: &cvssv2.EnvironmentalMetrics{
					CollateralDamagePotential:  cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_HIGH,
					TargetDistribution:         cvssv2.TargetDistribution_TARGET_DISTRIBUTION_HIGH,
					ConfidentialityRequirement: cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH,
					IntegrityRequirement:       cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH,
					AvailabilityRequirement:    cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH,
				},
			},
			expectedResult: "AV:N/AC:H/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:H/AR:H",
		},
	}

	for _, tc := range tcl {
		t.Run(tc.name, func(t *testing.T) {
			result, err := vector.ToString(tc.vector)
			if tc.expectedErr && err == nil {
				t.Errorf("error expeced, but error was nil")
			}
			if result != tc.expectedResult {
				t.Errorf("got '%s', expected '%s' as result", result, tc.expectedResult)
			}
		})
	}
}

func TestVectorFromString(t *testing.T) {
	tcl := []struct {
		name           string
		input          string
		expectErr      bool
		expectedVector *cvssv2.Vector
	}{
		{
			name:      "blank string",
			input:     "",
			expectErr: true,
		},
		{
			name:      "fuzz: '//////' string",
			input:     "//////",
			expectErr: true,
		},
		{
			name:      "fuzz: 'A:ND/////' string",
			input:     "A:ND/////",
			expectErr: true,
		},
		{
			name:      "fuzz: 'Au:ND/////' string",
			input:     "Au:ND/////",
			expectErr: true,
		},
		{
			name:      "fuzz: 'AV:ND/////' string",
			input:     "AC:ND/////",
			expectErr: true,
		},
		{
			name:      "invalid part length",
			input:     "AV:N/AC:H/Au:N",
			expectErr: true,
		},
		{
			name:      "invalid part element",
			input:     "AV:N/AX:H/Au:N/C:C/I:C/A:C",
			expectErr: true,
		},
		{
			name:      "invalid part element in temporal",
			input:     "AV:N/AC:H/Au:N/C:C/I:C/A:C/X:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H",
			expectErr: true,
		},
		{
			name:      "invalid part element in environmental",
			input:     "AV:N/AC:H/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CRX:H/IR:H/AR:H",
			expectErr: true,
		},
		{
			name:      "invalid part value",
			input:     "AV:N/AC:X/Au:N/C:C/I:C/A:C",
			expectErr: true,
		},
		{
			name:      "full vector string",
			input:     "AV:N/AC:H/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H",
			expectErr: false,
			expectedVector: &cvssv2.Vector{
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
			},
		},
		{
			name:      "partial vector string",
			input:     "AV:N/AC:H/Au:N/C:C/I:C/A:C",
			expectErr: false,
			expectedVector: &cvssv2.Vector{
				BaseMetrics: &cvssv2.BaseMetrics{
					AccessVector:          cvssv2.AccessVector_ACCESS_VECTOR_NETWORK,
					AccessComplexity:      cvssv2.AccessComplexity_ACCESS_COMPLEXITY_HIGH,
					Authentication:        cvssv2.Authentication_AUTHENTICATION_NONE,
					ConfidentialityImpact: cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_COMPLETE,
					IntegrityImpact:       cvssv2.IntegrityImpact_INTEGRITY_IMPACT_COMPLETE,
					AvailabilityImpact:    cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_COMPLETE,
				},
			},
		},
	}

	for _, tc := range tcl {
		t.Run(tc.name, func(t *testing.T) {
			result, err := vector.FromString(tc.input)
			if tc.expectErr && err == nil {
				t.Errorf("error expected, but error was nil")
			}
			if !cmp.Equal(result, tc.expectedVector) {
				t.Errorf("got %v, expected %v", result, tc.expectedVector)
			}
		})
	}
}

// ----------------------------------------------------------------------------------------------------------

func BenchmarkVectorToString(b *testing.B) {
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
		vector.ToString(v)
	}
}

func BenchmarkVectorFromString(b *testing.B) {
	vs := "AV:N/AC:H/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H"

	for i := 0; i < b.N; i++ {
		vector.FromString(vs)
	}
}
