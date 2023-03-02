package score_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	cvssv3 "github.com/zntrio/mitre/api/mitre/cvss/v3"
	"github.com/zntrio/mitre/cvss/v3/score"
)

var (
	cmpOpts = []cmp.Option{
		cmpopts.IgnoreUnexported(cvssv3.Vector{}),
		cmpopts.IgnoreUnexported(cvssv3.BaseMetrics{}),
		cmpopts.IgnoreUnexported(cvssv3.Score{}),
		cmpopts.IgnoreUnexported(cvssv3.BaseScore{}),
	}
)

func TestScoreEvaluate(t *testing.T) {
	tcl := []struct {
		name           string
		vector         *cvssv3.Vector
		expectErr      bool
		expectedResult *cvssv3.Score
	}{
		{
			name:      "nil vector",
			expectErr: true,
		},
		{
			name:      "empty vector",
			vector:    &cvssv3.Vector{},
			expectErr: true,
		},
		{
			name: "valid vector",
			vector: &cvssv3.Vector{
				BaseMetrics: &cvssv3.BaseMetrics{
					AttackVector:          cvssv3.AttackVector_ATTACK_VECTOR_NETWORK,
					AttackComplexity:      cvssv3.AttackComplexity_ATTACK_COMPLEXITY_LOW,
					PrivilegeRequired:     cvssv3.PrivilegeRequired_PRIVILEGE_REQUIRED_NONE,
					UserInteraction:       cvssv3.UserInteraction_USER_INTERACTION_NONE,
					Scope:                 cvssv3.Scope_SCOPE_CHANGED,
					ConfidentialityImpact: cvssv3.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_HIGH,
					IntegrityImpact:       cvssv3.IntegrityImpact_INTEGRITY_IMPACT_HIGH,
					AvailabilityImpact:    cvssv3.AvailabilityImpact_AVAILABILITY_IMPACT_HIGH,
				},
			},
			expectErr: false,
			expectedResult: &cvssv3.Score{
				BaseScore: &cvssv3.BaseScore{
					AttackVector:          0.85,
					AttackComplexity:      0.77,
					PrivilegeRequired:     0.85,
					UserInteraction:       0.85,
					ConfidentialityImpact: 0.56,
					IntegrityImpact:       0.56,
					AvailabilityImpact:    0.56,
					Exploitability:        3.9,
					Impact:                6.0,
					Score:                 10.0,
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
			if !cmp.Equal(tc.expectedResult, result, cmpOpts...) {
				t.Errorf("got %q, expected to equal %q", result, tc.expectedResult)
			}
		})
	}
}

func BenchmarkScoreEvaluate(b *testing.B) {
	v := &cvssv3.Vector{
		BaseMetrics: &cvssv3.BaseMetrics{
			AttackVector:          cvssv3.AttackVector_ATTACK_VECTOR_NETWORK,
			AttackComplexity:      cvssv3.AttackComplexity_ATTACK_COMPLEXITY_LOW,
			PrivilegeRequired:     cvssv3.PrivilegeRequired_PRIVILEGE_REQUIRED_NONE,
			UserInteraction:       cvssv3.UserInteraction_USER_INTERACTION_NONE,
			Scope:                 cvssv3.Scope_SCOPE_CHANGED,
			ConfidentialityImpact: cvssv3.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_HIGH,
			IntegrityImpact:       cvssv3.IntegrityImpact_INTEGRITY_IMPACT_HIGH,
			AvailabilityImpact:    cvssv3.AvailabilityImpact_AVAILABILITY_IMPACT_HIGH,
		},
	}

	for i := 0; i < b.N; i++ {
		score.Evaluate(v)
	}
}
