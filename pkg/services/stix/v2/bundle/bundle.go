package bundle

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"golang.org/x/xerrors"

	stixv2 "go.zenithar.org/mitre/pkg/protocol/mitre/stix/v2"
)

// Bundle represents STIX object bundle (i.e. ATT&CK)
type Bundle struct {
	Type        string        `json:"type"`
	ID          string        `json:"id"`
	SpecVersion string        `json:"spec_version"`
	Objects     []interface{} `json:"objects"`
}

// Stats represents bundle loading stats
type Stats struct {
	Count        int64
	CountPerType map[string]int64
	Elapsed      int64
}

// -----------------------------------------------------------------

// Decode an object bundle
func Decode(reader io.Reader) (*Bundle, *Stats, error) {

	// Add start clock
	start := time.Now().UTC()

	// Unmarshal to bundle
	var b jsonBundle
	if err := json.NewDecoder(reader).Decode(&b); err != nil {
		return nil, nil, xerrors.Errorf("bundle: unable to decode bundle: %w", err)
	}

	// Initialize a bundle
	res := &Bundle{
		Type:        b.Type,
		ID:          b.ID,
		SpecVersion: b.SpecVersion,
		Objects:     make([]interface{}, len(b.Objects)),
	}

	stats := &Stats{
		Count:        0,
		CountPerType: map[string]int64{},
	}

	// Assign all objects
	for i, obj := range b.Objects {
		// Increment global counter
		stats.Count++

		// Assign object
		res.Objects[i] = obj.Object

		// Increment type counter
		_, ok := stats.CountPerType[obj.Type]
		if !ok {
			stats.CountPerType[obj.Type] = 0
		}
		stats.CountPerType[obj.Type]++
	}

	// Stop clock
	end := time.Now().UTC()
	stats.Elapsed = int64(end.Nanosecond() - start.Nanosecond())

	// Return result
	return res, stats, nil
}

// -----------------------------------------------------------------

// Bundle describe a STIX objects bundle
type jsonBundle struct {
	Type        string       `json:"type"`
	ID          string       `json:"id"`
	SpecVersion string       `json:"spec_version"`
	Objects     []jsonObject `json:"objects"`
}

type jsonObject struct {
	Type   string      `json:"type"`
	Object interface{} `json:"-"`
}

func (o *jsonObject) UnmarshalJSON(b []byte) error {
	var meta map[string]*json.RawMessage
	if err := json.Unmarshal(b, &meta); err != nil {
		return xerrors.Errorf("bundle: unable to unmarshal bundle object : %w", err)
	}

	if t, ok := meta["type"]; ok {
		if err := json.Unmarshal(*t, &o.Type); err != nil {
			return xerrors.Errorf("bundle: unable to unmarshal 'type' value : %w", err)
		}

		if strings.HasPrefix(o.Type, "x-") {
			o.Object = &map[string]interface{}{}
		} else {
			switch o.Type {
			case "attack-pattern":
				o.Object = &stixv2.AttackPattern{}
			case "campaign":
				o.Object = &stixv2.Campaign{}
			case "course-of-action":
				o.Object = &stixv2.CourseOfAction{}
			case "identity":
				o.Object = &stixv2.Identity{}
			case "indicator":
				o.Object = &stixv2.Indicator{}
			case "intrusion-set":
				o.Object = &stixv2.IntrusionSet{}
			case "malware":
				o.Object = &stixv2.Malware{}
			case "marking-definition":
				o.Object = &stixv2.MarkingDefinition{}
			case "observed-data":
				o.Object = &stixv2.ObservedData{}
			case "report":
				o.Object = &stixv2.Report{}
			case "threat-actor":
				o.Object = &stixv2.ThreatActor{}
			case "tool":
				o.Object = &stixv2.Tool{}
			case "vulnerability":
				o.Object = &stixv2.Vulnerability{}
			case "relationship":
				o.Object = &stixv2.RelationShip{}
			case "sighting":
				o.Object = &stixv2.Sighting{}
			default:
				return xerrors.Errorf("bundle: unable to decode object, unhandled '%s' type", o.Type)
			}
		}

		// Decode as new object
		if err := json.Unmarshal(b, o.Object); err != nil {
			return xerrors.Errorf("bundle: unable to decode '%s' object : %w", o.Type, err)
		}
	} else {
		return xerrors.New("bundle: bundle object must contain a 'type' property")
	}

	return nil
}
