package bundle

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
}
