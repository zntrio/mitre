package score

import (
	"math"

	cvssv3 "github.com/zntrio/mitre/api/mitre/cvss/v3"
)

func weightAttackVector(av cvssv3.AttackVector) float64 {
	switch av {
	case cvssv3.AttackVector_ATTACK_VECTOR_NETWORK:
		return 0.85
	case cvssv3.AttackVector_ATTACK_VECTOR_ADJACENT:
		return 0.62
	case cvssv3.AttackVector_ATTACK_VECTOR_LOCAL:
		return 0.55
	}

	// Local / Physical
	return 0.2
}

func weightAttackComplexity(ac cvssv3.AttackComplexity) float64 {
	switch ac {
	case cvssv3.AttackComplexity_ATTACK_COMPLEXITY_LOW:
		return 0.77
	}

	// High
	return 0.44
}

func weightPrivilegeRequired(pr cvssv3.PrivilegeRequired, scope cvssv3.Scope) float64 {
	switch pr {
	case cvssv3.PrivilegeRequired_PRIVILEGE_REQUIRED_HIGH:
		switch scope {
		case cvssv3.Scope_SCOPE_CHANGED:
			return 0.50
		case cvssv3.Scope_SCOPE_UNCHANGED:
			return 0.27
		}
	case cvssv3.PrivilegeRequired_PRIVILEGE_REQUIRED_LOW:
		switch scope {
		case cvssv3.Scope_SCOPE_CHANGED:
			return 0.68
		case cvssv3.Scope_SCOPE_UNCHANGED:
			return 0.62
		}
	}

	// None
	return 0.85
}

func weightUserInteraction(ui cvssv3.UserInteraction) float64 {
	switch ui {
	case cvssv3.UserInteraction_USER_INTERACTION_REQUIRED:
		return 0.62
	}

	// Required
	return 0.85
}

func weightConfidentiality(i cvssv3.ConfidentialityImpact) float64 {
	switch i {
	case cvssv3.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_LOW:
		return 0.22
	case cvssv3.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_HIGH:
		return 0.56
	}

	// None
	return 0.0
}

func weightIntegrity(i cvssv3.IntegrityImpact) float64 {
	switch i {
	case cvssv3.IntegrityImpact_INTEGRITY_IMPACT_LOW:
		return 0.22
	case cvssv3.IntegrityImpact_INTEGRITY_IMPACT_HIGH:
		return 0.56
	}

	// None
	return 0.0
}

func weightAvailability(i cvssv3.AvailabilityImpact) float64 {
	switch i {
	case cvssv3.AvailabilityImpact_AVAILABILITY_IMPACT_LOW:
		return 0.22
	case cvssv3.AvailabilityImpact_AVAILABILITY_IMPACT_HIGH:
		return 0.56
	}

	// None
	return 0.0
}

func impactScore(bm *cvssv3.BaseMetrics) float64 {
	isc := iscBase(bm)

	switch bm.Scope {
	case cvssv3.Scope_SCOPE_CHANGED:
		// 7.52 × [ISCBase−0.029] − 3.25 × [ISCBase−0.02]^15
		return 7.52*(isc-0.029) - 3.25*math.Pow((isc-0.02), 15.0)
	}
	// Unchanged
	return 6.42 * isc
}

// ISCBase = 1 - [(1−ImpactConf) × (1−ImpactInteg) × (1−ImpactAvail)]
func iscBase(bm *cvssv3.BaseMetrics) float64 {
	return float64(1.0 - (1.0-weightConfidentiality(bm.ConfidentialityImpact))*(1.0-weightIntegrity(bm.IntegrityImpact))*(1.0-weightAvailability(bm.AvailabilityImpact)))
}

// 8.22 × AttackVector × AttackComplexity × PrivilegeRequired × UserInteraction
func exploitabilityScore(bm *cvssv3.BaseMetrics) float64 {
	return 8.22 * weightAttackVector(bm.AttackVector) * weightAttackComplexity(bm.AttackComplexity) * weightPrivilegeRequired(bm.PrivilegeRequired, bm.Scope) * weightUserInteraction(bm.UserInteraction)
}

// If (Impact sub score <= 0) 0 else,
// Scope Unchanged[4] Round up (Minimum [(Impact + Exploitability), 10])
// Scope Changed Round up (Minimum [1.08 × (Impact + Exploitability), 10])
func baseScore(v *cvssv3.Vector) float64 {
	impact := impactScore(v.BaseMetrics)
	if impact <= 0 {
		return 0.0
	}

	exploitability := exploitabilityScore(v.BaseMetrics)

	coeff := 1.0
	switch v.BaseMetrics.Scope {
	case cvssv3.Scope_SCOPE_CHANGED:
		coeff = 1.08
	default:
		coeff = 1.0
	}

	return roundUp1(math.Min(coeff*(impact+exploitability), 10.0))
}

func roundUp1(val float64) float64 {
	return math.Round(val*10) / 10
}
