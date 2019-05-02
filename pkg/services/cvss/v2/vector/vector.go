package vector

import (
	"fmt"
	"strings"

	cvssv2 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v2"
	"golang.org/x/xerrors"
)

// ------------------------------------------------------------------------

// ToString returns CVSS vector string representations
func ToString(v *cvssv2.Vector) (string, error) {

	if v == nil {
		return "", xerrors.New("vector: unable to generate vector string of nil vector")
	}
	if v.BaseMetrics == nil {
		return "", xerrors.New("vector: invalid vector, base metrics should not be nil")

	}

	res := baseVector(v.BaseMetrics)
	if v.TemporalMetrics != nil {
		res = fmt.Sprintf("%s/%s", res, temporalVector(v.TemporalMetrics))
	}
	if v.EnvironmentalMetrics != nil {
		res = fmt.Sprintf("%s/%s", res, environmentalVector(v.EnvironmentalMetrics))
	}

	return res, nil
}

// FromString builds a vector instance from a vector string
func FromString(vs string) (*cvssv2.Vector, error) {
	// Split vector string as elements
	parts := strings.Split(vs, "/")

	if len(parts) < 6 {
		return nil, xerrors.New("vector: invalid vector string, it should contains at least 6 fields")
	}

	res := &cvssv2.Vector{}

	// AV:ND/AC:ND/Au:ND/C:ND/I:ND/A:ND/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND
	for _, part := range parts {
		err := applyMetricPart(res, part)
		if err != nil {
			return nil, xerrors.Errorf("vector: unable to parse vector string : %w", err)
		}
	}

	return res, nil
}

// ------------------------------------------------------------------------
const (
	notDefined = "ND"
)

func baseVector(bm *cvssv2.BaseMetrics) string {
	return fmt.Sprintf("AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s",
		mustString(accessVector.ByKey, bm.AccessVector, notDefined),
		mustString(accessComplexity.ByKey, bm.AccessComplexity, notDefined),
		mustString(authentication.ByKey, bm.Authentication, notDefined),
		mustString(confidentialityImpact.ByKey, bm.ConfidentialityImpact, notDefined),
		mustString(integrityImpact.ByKey, bm.IntegrityImpact, notDefined),
		mustString(availabilityImpact.ByKey, bm.AvailabilityImpact, notDefined),
	)
}

func temporalVector(tm *cvssv2.TemporalMetrics) string {
	return fmt.Sprintf("E:%s/RL:%s/RC:%s",
		mustString(exploitability.ByKey, tm.Exploitability, notDefined),
		mustString(remediationLevel.ByKey, tm.RemediationLevel, notDefined),
		mustString(reportConfidence.ByKey, tm.ReportConfidence, notDefined),
	)
}

func environmentalVector(em *cvssv2.EnvironmentalMetrics) string {
	return fmt.Sprintf("CDP:%s/TD:%s/CR:%s/IR:%s/AR:%s",
		mustString(collateralDamagePotential.ByKey, em.CollateralDamagePotential, notDefined),
		mustString(targetDistribution.ByKey, em.TargetDistribution, notDefined),
		mustString(securityRequirement.ByKey, em.ConfidentialityRequirement, notDefined),
		mustString(securityRequirement.ByKey, em.IntegrityRequirement, notDefined),
		mustString(securityRequirement.ByKey, em.AvailabilityRequirement, notDefined),
	)
}

func applyMetricPart(v *cvssv2.Vector, part string) error {
	var err error

	item := strings.SplitN(part, ":", 2)
	if len(item) != 2 {
		return xerrors.New("vector: invalid vector string component, it should contains be formatted as 'key:value'")
	}

	switch item[0] {
	// Base Metrics
	case "AC", "AV", "Au", "C", "I", "A":
		if v.BaseMetrics == nil {
			v.BaseMetrics = &cvssv2.BaseMetrics{}
		}
		err = applyBaseMetrics(v.BaseMetrics, item[0], item[1])
	// Temporal metrics
	case "E", "RL", "RC":
		if v.TemporalMetrics == nil {
			v.TemporalMetrics = &cvssv2.TemporalMetrics{}
		}
		err = applyTemporalMetrics(v.TemporalMetrics, item[0], item[1])
	// Environmental metrics
	case "CDP", "TD", "CR", "IR", "AR":
		if v.EnvironmentalMetrics == nil {
			v.EnvironmentalMetrics = &cvssv2.EnvironmentalMetrics{}
		}
		err = applyEnvironmentalMetrics(v.EnvironmentalMetrics, item[0], item[1])
	default:
		err = xerrors.Errorf("vector: invalid vector string component '%q' with value '%q'", item[0], item[1])
	}

	// No error
	return err
}

func applyBaseMetrics(bm *cvssv2.BaseMetrics, category string, value string) error {
	var err error

	switch category {
	case "AC": // Access Complexity
		bm.AccessComplexity = mustValue(accessComplexity.ByValue, value, cvssv2.AccessComplexity_ACCESS_COMPLEXITY_INVALID, &err).(cvssv2.AccessComplexity)
	case "AV": // Access Vector
		bm.AccessVector = mustValue(accessVector.ByValue, value, cvssv2.AccessVector_ACCESS_VECTOR_INVALID, &err).(cvssv2.AccessVector)
	case "Au": // Authetication
		bm.Authentication = mustValue(authentication.ByValue, value, cvssv2.Authentication_AUTHENTICATION_INVALID, &err).(cvssv2.Authentication)
	case "C": // Confidentiality
		bm.ConfidentialityImpact = mustValue(confidentialityImpact.ByValue, value, cvssv2.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_INVALID, &err).(cvssv2.ConfidentialityImpact)
	case "I": // Integrity
		bm.IntegrityImpact = mustValue(integrityImpact.ByValue, value, cvssv2.IntegrityImpact_INTEGRITY_IMPACT_INVALID, &err).(cvssv2.IntegrityImpact)
	case "A": // Availability
		bm.AvailabilityImpact = mustValue(availabilityImpact.ByValue, value, cvssv2.AvailabilityImpact_AVAILABILITY_IMPACT_INVALID, &err).(cvssv2.AvailabilityImpact)
	default:
		return xerrors.Errorf("vector: unable to apply %q with value %q on base metrics", category, value)
	}

	// Return error
	return err
}

func applyTemporalMetrics(tm *cvssv2.TemporalMetrics, category string, value string) error {
	var err error

	switch category {
	case "E": // Exploitability
		tm.Exploitability = mustValue(exploitability.ByValue, value, cvssv2.Exploitability_EXPLOITABILITY_INVALID, &err).(cvssv2.Exploitability)
	case "RL": // Remediation Level
		tm.RemediationLevel = mustValue(remediationLevel.ByValue, value, cvssv2.RemediationLevel_REMEDIATION_LEVEL_INVALID, &err).(cvssv2.RemediationLevel)
	case "RC": // Report Confidence
		tm.ReportConfidence = mustValue(reportConfidence.ByValue, value, cvssv2.ReportConfidence_REPORT_CONFIDENCE_INVALID, &err).(cvssv2.ReportConfidence)
	default:
		return xerrors.Errorf("vector: unable to apply %q with value %q on temporal metrics", category, value)
	}

	// Return error
	return err
}

func applyEnvironmentalMetrics(em *cvssv2.EnvironmentalMetrics, category string, value string) error {
	var err error

	switch category {
	case "CDP": // Collateral
		em.CollateralDamagePotential = mustValue(collateralDamagePotential.ByValue, value, cvssv2.CollateralDamagePotential_COLLATERAL_DAMAGE_POTENTIAL_INVALID, &err).(cvssv2.CollateralDamagePotential)
	case "TD": // Target Distribution
		em.TargetDistribution = mustValue(targetDistribution.ByValue, value, cvssv2.TargetDistribution_TARGET_DISTRIBUTION_INVALID, &err).(cvssv2.TargetDistribution)
	case "CR": // Confidentiality Requirement
		em.ConfidentialityRequirement = mustValue(securityRequirement.ByValue, value, cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_INVALID, &err).(cvssv2.SecurityRequirement)
	case "IR": // Integrity Requirement
		em.IntegrityRequirement = mustValue(securityRequirement.ByValue, value, cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_INVALID, &err).(cvssv2.SecurityRequirement)
	case "AR": // Availability Requirement
		em.AvailabilityRequirement = mustValue(securityRequirement.ByValue, value, cvssv2.SecurityRequirement_SECURITY_REQUIREMENT_INVALID, &err).(cvssv2.SecurityRequirement)
	default:
		return xerrors.Errorf("vector: unable to apply %q with value %q on enviromental metrics", category, value)
	}

	// Return error
	return err
}

func mustString(call func(interface{}) (out interface{}, err error), in interface{}, fallback string) string {
	out, err := call(in)
	if err != nil {
		return fallback
	}
	return out.(string)
}

func mustValue(call func(interface{}) (out interface{}, err error), in interface{}, fallback interface{}, err *error) interface{} {
	out, errCall := call(in)
	if errCall != nil {
		*err = errCall
		return fallback
	}
	return out
}
