package vector

import (
	cvssv3 "github.com/zntrio/mitre/api/mitre/cvss/v3"
	"golang.org/x/xerrors"
)

// ------------------------------------------------------------------------

// ToString returns CVSS vector string representations
func ToString(v *cvssv3.Vector) (string, error) {
	if v == nil {
		return "", xerrors.New("vector: unable to generate vector string of nil vector")
	}
	if v.BaseMetrics == nil {
		return "", xerrors.New("vector: invalid vector, base metrics should not be nil")

	}

	res := baseVector(v.BaseMetrics)
	/*	if v.TemporalMetrics != nil {
			res = fmt.Sprintf("%s/%s", res, temporalVector(v.TemporalMetrics))
		}
		if v.EnvironmentalMetrics != nil {
			res = fmt.Sprintf("%s/%s", res, environmentalVector(v.EnvironmentalMetrics))
		}*/

	return res, nil
}

// FromString builds a vector instance from a vector string
func FromString(vs string) (*cvssv3.Vector, error) {
	return nil, nil
}

// ------------------------------------------------------------------------
