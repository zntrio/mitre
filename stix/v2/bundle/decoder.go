package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	jsoniter "github.com/json-iterator/go"
	stixv2 "github.com/zntrio/mitre/api/mitre/stix/v2"
	"golang.org/x/xerrors"
)

// Decode an object bundle
func Decode(reader io.Reader) (*Bundle, *Stats, error) {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary

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

	// Initialize stats result
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

	// Return result
	return res, stats, nil
}

// -----------------------------------------------------------------

var typeMap = map[string]func() interface{}{
	"attack-pattern":     func() interface{} { return &stixv2.AttackPattern{} },
	"campaign":           func() interface{} { return &stixv2.Campaign{} },
	"course-of-action":   func() interface{} { return &stixv2.CourseOfAction{} },
	"identity":           func() interface{} { return &stixv2.Identity{} },
	"indicator":          func() interface{} { return &stixv2.Indicator{} },
	"intrusion-set":      func() interface{} { return &stixv2.IntrusionSet{} },
	"malware":            func() interface{} { return &stixv2.Malware{} },
	"observed-data":      func() interface{} { return &stixv2.ObservedData{} },
	"report":             func() interface{} { return &stixv2.Report{} },
	"threat-actor":       func() interface{} { return &stixv2.ThreatActor{} },
	"tool":               func() interface{} { return &stixv2.Tool{} },
	"vulnerability":      func() interface{} { return &stixv2.Vulnerability{} },
	"relationship":       func() interface{} { return &stixv2.RelationShip{} },
	"sighting":           func() interface{} { return &stixv2.Sighting{} },
	"marking-definition": func() interface{} { return &stixv2.MarkingDefinition{} },
}

// RegisterType register a new type association and a builder for deserialization
func RegisterType(name string, builder func() interface{}) error {
	if _, ok := typeMap[name]; !ok {
		typeMap[name] = builder
		return nil
	}

	return xerrors.Errorf("bundle: can't register builder, type '%s' already registered", name)
}

// ReplaceType is used to replace a type with new builder. For Example for attribute extensions (Mitre Att&ck)
func ReplaceType(name string, builder func() interface{}) error {
	if _, ok := typeMap[name]; ok {
		typeMap[name] = builder
		return nil
	}

	return xerrors.Errorf("bundle: can't replace not registered builder, type '%s' not registered", name)
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
	var jsoni = jsoniter.ConfigCompatibleWithStandardLibrary

	// Extract meta from object
	var meta map[string]*json.RawMessage
	if err := jsoni.Unmarshal(b, &meta); err != nil {
		return fmt.Errorf("bundle: unable to unmarshal bundle object : %w", err)
	}

	if t, ok := meta["type"]; ok {
		if t == nil {
			return errors.New("bundle: type attribute found but has nil value")
		}

		// Unmarshal type meta to use as selector
		if err := jsoni.Unmarshal(*t, &o.Type); err != nil {
			return fmt.Errorf("bundle: unable to unmarshal 'type' value : %w", err)
		}

		// Find type builder according meta type
		if builder, ok := typeMap[o.Type]; ok {
			o.Object = builder()
		} else {
			return fmt.Errorf("bundle: unable to find type builder for '%s'", o.Type)
		}

		// Decode as new object
		if err := jsoni.Unmarshal(b, o.Object); err != nil {
			return fmt.Errorf("bundle: unable to decode '%s' object : %w", o.Type, err)
		}
	} else {
		return errors.New("bundle: bundle object must contain a 'type' property")
	}

	return nil
}
