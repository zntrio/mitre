package vector

import (
	"errors"
	"fmt"

	cvssv2 "github.com/zntrio/mitre/api/mitre/cvss/v2"
)

type mapResolver struct {
	keyMap   map[interface{}]interface{}
	valueMap map[interface{}]interface{}
}

func newResolver(items ...interface{}) *mapResolver {
	itemLen := len(items)
	if itemLen%2 != 0 {
		panic(errors.New("Items length should a multiple of 2"))
	}

	// Initialise maps
	keyMap := map[interface{}]interface{}{}
	valueMap := map[interface{}]interface{}{}

	i := 0
	for i < itemLen {
		keyMap[items[i]] = items[i+1]
		valueMap[items[i+1]] = items[i]
		i = i + 2
	}

	// return resolver
	return &mapResolver{
		keyMap:   keyMap,
		valueMap: valueMap,
	}
}

func (r *mapResolver) ByKey(k interface{}) (interface{}, error) {
	item, ok := r.keyMap[k]
	if !ok {
		return nil, fmt.Errorf("vector: unable to retrieve %q as key", k)
	}

	// return result
	return item, nil
}

func (r *mapResolver) ByValue(k interface{}) (interface{}, error) {
	item, ok := r.valueMap[k]
	if !ok {
		return nil, fmt.Errorf("vector: unable to retrieve %q as value", k)
	}

	// return result
	return item, nil
}

// ---------------------------------------------------------------------------

var (
	accessVector              *mapResolver
	accessComplexity          *mapResolver
	authentication            *mapResolver
	confidentialityImpact     *mapResolver
	integrityImpact           *mapResolver
	availabilityImpact        *mapResolver
	exploitability            *mapResolver
	remediationLevel          *mapResolver
	reportConfidence          *mapResolver
	collateralDamagePotential *mapResolver
	targetDistribution        *mapResolver
	securityRequirement       *mapResolver
)

func init() {
	accessVector = newResolver(
		cvssv2.AccessVector_ACCESS_VECTOR_LOCAL, "L",
		cvssv2.AccessVector_ACCESS_VECTOR_ADJACENT_NETWORK, "A",
		cvssv2.AccessVector_ACCESS_VECTOR_NETWORK, "N",
		cvssv2.AccessVector_ACCESS_VECTOR_UNDEFINED, "ND",
	)
	accessComplexity = newResolver(
		cvssv2.AccessComplexity_ACCESS_COMPLEXITY_HIGH, "H",
		cvssv2.AccessComplexity_ACCESS_COMPLEXITY_MEDIUM, "M",
		cvssv2.AccessComplexity_ACCESS_COMPLEXITY_LOW, "L",
		cvssv2.AccessComplexity_ACCESS_COMPLEXITY_UNDEFINED, "ND",
	)
	authentication = newResolver(
		cvssv2.Authentication_AUTHENTICATION_MULTIPLE, "M",
		cvssv2.Authentication_AUTHENTICATION_SINGLE, "S",
		cvssv2.Authentication_AUTHENTICATION_NONE, "N",
		cvssv2.Authentication_AUTHENTICATION_UNDEFINED, "ND",
	)
	confidentialityImpact = newResolver(
		cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_NONE, "N",
		cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_PARTIAL, "P",
		cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_COMPLETE, "C",
		cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_UNDEFINED, "ND",
	)
	integrityImpact = newResolver(
		cvssv2.IntegrityImpact_INTEGRITY_IMPACT_NONE, "N",
		cvssv2.IntegrityImpact_INTEGRITY_IMPACT_PARTIAL, "P",
		cvssv2.IntegrityImpact_INTEGRITY_IMPACT_COMPLETE, "C",
		cvssv2.IntegrityImpact_INTEGRITY_IMPACT_UNDEFINED, "ND",
	)
	availabilityImpact = newResolver(
		cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_NONE, "N",
		cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_PARTIAL, "P",
		cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_COMPLETE, "C",
		cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_UNDEFINED, "ND",
	)
	exploitability = newResolver(
		cvssv2.Exploitability_EXPLOITABILITY_UNPROVEN, "U",
		cvssv2.Exploitability_EXPLOITABILITY_PROOF_OF_CONCEPT, "POC",
		cvssv2.Exploitability_EXPLOITABILITY_FUNCTIONAL, "F",
		cvssv2.Exploitability_EXPLOITABILITY_HIGH, "H",
		cvssv2.Exploitability_EXPLOITABILITY_NOT_DEFINED, "ND",
	)
	remediationLevel = newResolver(
		cvssv2.RemediationLevel_REMEDIATION_LEVEL_OFFICIAL_FIX, "OF",
		cvssv2.RemediationLevel_REMEDIATION_LEVEL_TEMPORARY_FIX, "TF",
		cvssv2.RemediationLevel_REMEDIATION_LEVEL_WORKAROUND, "W",
		cvssv2.RemediationLevel_REMEDIATION_LEVEL_UNAVAILABLE, "U",
		cvssv2.RemediationLevel_REMEDIATION_LEVEL_NO_DEFINED, "ND",
	)
	reportConfidence = newResolver(
		cvssv2.ReportConfidence_REPORT_CONFIDENCE_UNCONFIRMED, "UC",
		cvssv2.ReportConfidence_REPORT_CONFIDENCE_UNCORROBORATED, "UR",
		cvssv2.ReportConfidence_REPORT_CONFIDENCE_CONFIRMED, "C",
		cvssv2.ReportConfidence_REPORT_CONFIDENCE_NOT_DEFINED, "ND",
	)
	collateralDamagePotential = newResolver(
		cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_NONE, "N",
		cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_LOW, "L",
		cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_LOW_MEDIUM, "LM",
		cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_MEDIUM_HIGH, "MH",
		cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_HIGH, "H",
		cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_NOT_DEFINED, "ND",
	)
	targetDistribution = newResolver(
		cvssv2.TargetDistribution_TARGET_DISTRIBUTION_NONE, "N",
		cvssv2.TargetDistribution_TARGET_DISTRIBUTION_LOW, "L",
		cvssv2.TargetDistribution_TARGET_DISTRIBUTION_MEDIUM, "M",
		cvssv2.TargetDistribution_TARGET_DISTRIBUTION_HIGH, "H",
		cvssv2.TargetDistribution_TARGET_DISTRIBUTION_NOT_DEFINED, "ND",
	)
	securityRequirement = newResolver(
		cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_LOW, "L",
		cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_MEDIUM, "M",
		cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_HIGH, "H",
		cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_NOT_DEFINED, "ND",
	)
}
