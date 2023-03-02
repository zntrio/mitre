package score

import (
	"fmt"
	"math"
	"strconv"

	cvssv2 "github.com/zntrio/mitre/api/mitre/cvss/v2"
)

// ---------------------------------------------------------------------
// Base Metric weights

func weightAccessVector(av cvssv2.AccessVector) float64 {
	switch av {
	case cvssv2.AccessVector_ACCESS_VECTOR_LOCAL:
		return 0.395
	case cvssv2.AccessVector_ACCESS_VECTOR_ADJACENT_NETWORK:
		return 0.646
	}

	// Network
	return 1.0
}

func weightAccessComplexity(ac cvssv2.AccessComplexity) float64 {
	switch ac {
	case cvssv2.AccessComplexity_ACCESS_COMPLEXITY_HIGH:
		return 0.35
	case cvssv2.AccessComplexity_ACCESS_COMPLEXITY_MEDIUM:
		return 0.61
	}

	// Low
	return 0.71
}

func weightAuthentication(au cvssv2.Authentication) float64 {
	switch au {
	case cvssv2.Authentication_AUTHENTICATION_MULTIPLE:
		return 0.45
	case cvssv2.Authentication_AUTHENTICATION_SINGLE:
		return 0.56
	}

	// None
	return 0.704
}

func weightConfImpact(c cvssv2.ConfidentialityImpact) float64 {
	switch c {
	case cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_NONE:
		return 0.0
	case cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_PARTIAL:
		return 0.275
	}

	// Complete
	return 0.660
}

func weightIntegImpact(c cvssv2.IntegrityImpact) float64 {
	switch c {
	case cvssv2.IntegrityImpact_INTEGRITY_IMPACT_NONE:
		return 0.0
	case cvssv2.IntegrityImpact_INTEGRITY_IMPACT_PARTIAL:
		return 0.275
	}

	// Complete
	return 0.660
}

func weightAvailImpact(c cvssv2.AvailabilityImpact) float64 {
	switch c {
	case cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_NONE:
		return 0.0
	case cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_PARTIAL:
		return 0.275
	}

	// Complete
	return 0.660
}

// ---------------------------------------------------------------------
// Base Metric formula

// BaseScore = round_to_1_decimal(
//
//		(
//		  (0.6*Impact)+(0.4*Exploitability)-1.5
//	 )*f(Impact)
//
// )
func baseScore(bm *cvssv2.BaseMetrics) float64 {
	impact := impactScore(bm)
	return roundTo1Decimal((0.6*impact + 0.4*exploitabilityScore(bm) - 1.5) * fimpactScore(impact))
}

// Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
func impactScore(bm *cvssv2.BaseMetrics) float64 {
	return roundTo1Decimal(10.41 * (1 - (1-weightConfImpact(bm.ConfidentialityImpact))*(1-weightIntegImpact(bm.IntegrityImpact))*(1-weightAvailImpact(bm.AvailabilityImpact))))
}

// f(impact)= 0 if Impact=0, 1.176 otherwise
func fimpactScore(impact float64) float64 {
	if impact == 0 {
		return 0.0
	}
	return 1.176
}

// Exploitability = 20* AccessVector*AccessComplexity*Authentication
func exploitabilityScore(bm *cvssv2.BaseMetrics) float64 {
	return roundTo1Decimal(20 * weightAccessVector(bm.AccessVector) * weightAccessComplexity(bm.AccessComplexity) * weightAuthentication(bm.Authentication))
}

func roundTo1Decimal(in float64) float64 {
	v, err := strconv.ParseFloat(fmt.Sprintf("%.1f", in), 64)
	if err != nil {
		panic(err)
	}
	return v
}

// ---------------------------------------------------------------------
// Temporal Metric weights

func weightExploitability(e cvssv2.Exploitability) float64 {
	switch e {
	case cvssv2.Exploitability_EXPLOITABILITY_UNPROVEN:
		return 0.85
	case cvssv2.Exploitability_EXPLOITABILITY_PROOF_OF_CONCEPT:
		return 0.90
	case cvssv2.Exploitability_EXPLOITABILITY_FUNCTIONAL:
		return 0.95
	}

	// HIGH / NOT DEFINED
	return 1.0
}

func weightRemediationLevel(rl cvssv2.RemediationLevel) float64 {
	switch rl {
	case cvssv2.RemediationLevel_REMEDIATION_LEVEL_OFFICIAL_FIX:
		return 0.87
	case cvssv2.RemediationLevel_REMEDIATION_LEVEL_TEMPORARY_FIX:
		return 0.90
	case cvssv2.RemediationLevel_REMEDIATION_LEVEL_WORKAROUND:
		return 0.95
	}

	// UNAVAILABLE / NOT DEFINED
	return 1.0
}

func weightReportConfidence(rc cvssv2.ReportConfidence) float64 {
	switch rc {
	case cvssv2.ReportConfidence_REPORT_CONFIDENCE_UNCONFIRMED:
		return 0.90
	case cvssv2.ReportConfidence_REPORT_CONFIDENCE_UNCORROBORATED:
		return 0.95
	}

	// Confirmed / NOT DEFINED
	return 1.0
}

// ---------------------------------------------------------------------
// Temporal Metric formula

func temporalScore(baseScore float64, tm *cvssv2.TemporalMetrics) float64 {
	return roundTo1Decimal(baseScore * weightExploitability(tm.Exploitability) * weightRemediationLevel(tm.RemediationLevel) * weightReportConfidence(tm.ReportConfidence))
}

// ---------------------------------------------------------------------
// Environmental Metric weights

func weightCollateralDamagePotential(cdp cvssv2.CollateralDamagePotential) float64 {
	switch cdp {
	case cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_HIGH:
		return 0.5
	case cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH:
		return 0.4
	case cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM:
		return 0.3
	case cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_LOW:
		return 0.1
	}

	// None / Not Defined
	return 0.0
}

func weightTargetDistribution(td cvssv2.TargetDistribution) float64 {
	switch td {
	case cvssv2.TargetDistribution_TARGET_DISTRIBUTION_NONE:
		return 0.0
	case cvssv2.TargetDistribution_TARGET_DISTRIBUTION_LOW:
		return 0.25
	case cvssv2.TargetDistribution_TARGET_DISTRIBUTION_MEDIUM:
		return 0.75
	}

	// High / Not Defined
	return 1.00
}

func weightSecurityRequirement(sr cvssv2.SecurityRequirement) float64 {
	switch sr {
	case cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_LOW:
		return 0.5
	case cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH:
		return 1.51
	}

	// Medium / Not Defined
	return 1.0
}

// ---------------------------------------------------------------------
// Environmental Metric formula

// EnvironmentalScore = round_to_1_decimal(
//
//		(
//	   AdjustedTemporal+(10-AdjustedTemporal)*CollateralDamagePotential
//	 )*TargetDistribution
//
// )
func environmentalScore(v *cvssv2.Vector) float64 {
	temporal := adjustedTemporal(v)
	return roundTo1Decimal((temporal + (10-temporal)*weightCollateralDamagePotential(v.EnvironmentalMetrics.CollateralDamagePotential)) * weightTargetDistribution(v.EnvironmentalMetrics.TargetDistribution))
}

func adjustedBase(v *cvssv2.Vector) float64 {
	adjustedImpact := adjustedImpact(v.BaseMetrics, v.EnvironmentalMetrics)
	return roundTo1Decimal((0.6*adjustedImpact + 0.4*exploitabilityScore(v.BaseMetrics) - 1.5) * fimpactScore(adjustedImpact))
}

// AdjustedTemporal = TemporalScore recomputed with the BaseScore's Impact sub-equation replaced with the AdjustedImpact equation
func adjustedTemporal(v *cvssv2.Vector) float64 {
	return temporalScore(adjustedBase(v), v.TemporalMetrics)
}

// AdjustedImpact = min(10,10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)*(1-AvailImpact*AvailReq)))
func adjustedImpact(bm *cvssv2.BaseMetrics, em *cvssv2.EnvironmentalMetrics) float64 {
	conf := 1 - weightConfImpact(bm.ConfidentialityImpact)*weightSecurityRequirement(em.ConfidentialityRequirement)
	integ := 1 - weightIntegImpact(bm.IntegrityImpact)*weightSecurityRequirement(em.IntegrityRequirement)
	avail := 1 - weightAvailImpact(bm.AvailabilityImpact)*weightSecurityRequirement(em.AvailabilityRequirement)
	return math.Min(10, 10.41*(1-((conf)*(integ)*(avail))))
}
