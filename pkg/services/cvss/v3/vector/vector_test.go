package vector_test

import (
	"testing"

	cvssv3 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v3"
	"go.zenithar.org/mitre/pkg/services/cvss/v3/vector"
)

func TestVectorToString(t *testing.T) {
	tcl := []struct {
		name           string
		vector         *cvssv3.Vector
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
			vector:         &cvssv3.Vector{},
			expectedErr:    true,
			expectedResult: "",
		},
		{
			name: "empty sub metrics",
			vector: &cvssv3.Vector{
				BaseMetrics: &cvssv3.BaseMetrics{},
			},
			expectedResult: "AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X",
		},
		{
			name: "valid full vector",
			vector: &cvssv3.Vector{
				BaseMetrics: &cvssv3.BaseMetrics{
					AttackVector:          cvssv3.AttackVector_ATTACK_VECTOR_ADJACENT,
					AttackComplexity:      cvssv3.AttackComplexity_ATTACK_COMPLEXITY_LOW,
					PrivilegeRequired:     cvssv3.PrivilegeRequired_PRIVILEGE_REQUIRED_LOW,
					UserInteraction:       cvssv3.UserInteraction_USER_INTERACTION_NONE,
					Scope:                 cvssv3.Scope_SCOPE_UNCHANGED,
					ConfidentialityImpact: cvssv3.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_HIGH,
					IntegrityImpact:       cvssv3.IntegrityImpact_INTEGRITY_IMPACT_HIGH,
					AvailabilityImpact:    cvssv3.AvailabilityImpact_AVAILABILITY_IMPACT_HIGH,
				},
			},
			expectedResult: "AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
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

// ----------------------------------------------------------------------------------------------------------

func BenchmarkVectorToString(b *testing.B) {
	v := &cvssv3.Vector{
		BaseMetrics: &cvssv3.BaseMetrics{
			AttackVector:          cvssv3.AttackVector_ATTACK_VECTOR_ADJACENT,
			AttackComplexity:      cvssv3.AttackComplexity_ATTACK_COMPLEXITY_LOW,
			PrivilegeRequired:     cvssv3.PrivilegeRequired_PRIVILEGE_REQUIRED_LOW,
			UserInteraction:       cvssv3.UserInteraction_USER_INTERACTION_NONE,
			Scope:                 cvssv3.Scope_SCOPE_UNCHANGED,
			ConfidentialityImpact: cvssv3.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_HIGH,
			IntegrityImpact:       cvssv3.IntegrityImpact_INTEGRITY_IMPACT_HIGH,
			AvailabilityImpact:    cvssv3.AvailabilityImpact_AVAILABILITY_IMPACT_HIGH,
		},
	}

	for i := 0; i < b.N; i++ {
		vector.ToString(v)
	}
}
