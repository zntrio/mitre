package vector

import (
	"fmt"

	cvssv3 "go.zenithar.org/mitre/pkg/protocol/mitre/cvss/v3"
	"golang.org/x/xerrors"
)

// ------------------------------------------------------------------------

type mapResolver struct {
	keyMap   map[interface{}]interface{}
	valueMap map[interface{}]interface{}
}

func newResolver(items ...interface{}) *mapResolver {
	//

	itemLen := len(items)
	if itemLen%2 != 0 {
		panic(xerrors.New("Items length should a multiple of 2"))
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
		return nil, xerrors.Errorf("vector: unable to retrieve %q as key", k)
	}

	// return result
	return item, nil
}

func (r *mapResolver) ByValue(k interface{}) (interface{}, error) {
	item, ok := r.valueMap[k]
	if !ok {
		return nil, xerrors.Errorf("vector: unable to retrieve %q as value", k)
	}

	// return result
	return item, nil
}

// ------------------------------------------------------------------------

var (
	attackVector      *mapResolver
	attackComplexity  *mapResolver
	privilegeRequired *mapResolver
	userInteraction   *mapResolver
	scope             *mapResolver
	confidentiality   *mapResolver
	integrity         *mapResolver
	availability      *mapResolver
)

func init() {
	attackVector = newResolver(
		cvssv3.AttackVector_ATTACK_VECTOR_NETWORK, "N",
		cvssv3.AttackVector_ATTACK_VECTOR_ADJACENT, "A",
		cvssv3.AttackVector_ATTACK_VECTOR_LOCAL, "L",
		cvssv3.AttackVector_ATTACK_VECTOR_PHYSICAL, "P",
	)
	attackComplexity = newResolver(
		cvssv3.AttackComplexity_ATTACK_COMPLEXITY_LOW, "L",
		cvssv3.AttackComplexity_ATTACK_COMPLEXITY_HIGH, "H",
	)
	privilegeRequired = newResolver(
		cvssv3.PrivilegeRequired_PRIVILEGE_REQUIRED_NONE, "N",
		cvssv3.PrivilegeRequired_PRIVILEGE_REQUIRED_LOW, "L",
		cvssv3.PrivilegeRequired_PRIVILEGE_REQUIRED_HIGH, "H",
	)
	userInteraction = newResolver(
		cvssv3.UserInteraction_USER_INTERACTION_NONE, "N",
		cvssv3.UserInteraction_USER_INTERACTION_REQUIRED, "R",
	)
	scope = newResolver(
		cvssv3.Scope_SCOPE_UNCHANGED, "U",
		cvssv3.Scope_SCOPE_CHANGED, "C",
	)
	confidentiality = newResolver(
		cvssv3.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_HIGH, "H",
		cvssv3.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_LOW, "L",
		cvssv3.ConfidentialityImpact_CONFIDENTIALITY_IMPACT_NONE, "N",
	)
	integrity = newResolver(
		cvssv3.IntegrityImpact_INTEGRITY_IMPACT_HIGH, "H",
		cvssv3.IntegrityImpact_INTEGRITY_IMPACT_LOW, "L",
		cvssv3.IntegrityImpact_INTEGRITY_IMPACT_NONE, "N",
	)
	availability = newResolver(
		cvssv3.AvailabilityImpact_AVAILABILITY_IMPACT_HIGH, "H",
		cvssv3.AvailabilityImpact_AVAILABILITY_IMPACT_LOW, "L",
		cvssv3.AvailabilityImpact_AVAILABILITY_IMPACT_NONE, "N",
	)
}

// ------------------------------------------------------------------------

const (
	notDefined = "X"
)

func baseVector(bm *cvssv3.BaseMetrics) string {
	return fmt.Sprintf("AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		mustString(attackVector.ByKey, bm.AttackVector, notDefined),
		mustString(attackComplexity.ByKey, bm.AttackComplexity, notDefined),
		mustString(privilegeRequired.ByKey, bm.PrivilegeRequired, notDefined),
		mustString(userInteraction.ByKey, bm.UserInteraction, notDefined),
		mustString(scope.ByKey, bm.Scope, notDefined),
		mustString(confidentiality.ByKey, bm.ConfidentialityImpact, notDefined),
		mustString(integrity.ByKey, bm.IntegrityImpact, notDefined),
		mustString(availability.ByKey, bm.AvailabilityImpact, notDefined),
	)
}

func mustString(call func(interface{}) (out interface{}, err error), in interface{}, fallback string) string {
	out, err := call(in)
	if err != nil {
		return fallback
	}
	return out.(string)
}
