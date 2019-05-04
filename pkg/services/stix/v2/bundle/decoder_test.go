package bundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBundleDecoder(t *testing.T) {

	files := []string{
		"identifying-a-threat-actor-profile",
		"indicator-for-malicious-url",
		"malware-indicator-for-file-hash",
		"sighting-of-an-indicator",
		"sighting-of-observed-data",
		"ta-campaign",
		"threat-actor-leveraging-attack-patterns-and-malware",
		"using-granular-markings",
		"apt1",
		"poisonivy",
	}

	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			jsonFile, err := os.Open(filepath.Join("./internal/test/fixtures/", fmt.Sprintf("%s.json", f)))
			if err != nil {
				t.Errorf("unable to open fixture file: %v", err)
			}
			defer jsonFile.Close()

			_, _, err = Decode(jsonFile)
			if err != nil {
				t.Errorf("unable to deocde bundle: %v", err)
			}
		})
	}
}

func TestBundleDecoderWithExtension(t *testing.T) {

	err := RegisterType("location", func() interface{} { return &map[string]*json.RawMessage{} })
	if err != nil {
		t.Errorf("unable to register type extension: %v", err)
	}

	jsonFile, err := os.Open("./internal/test/fixtures/imddos.json")
	if err != nil {
		t.Errorf("unable to open fixture file: %v", err)
	}
	defer jsonFile.Close()

	_, _, err = Decode(jsonFile)
	if err != nil {
		t.Errorf("unable to deocde bundle: %v", err)
	}
}

func BenchmarkBundleLoader(b *testing.B) {
	jsonFile, err := os.Open("./internal/test/fixtures/identifying-a-threat-actor-profile.json")
	if err != nil {
		b.Errorf("unable to open fixture file: %v", err)
	}
	defer jsonFile.Close()

	for i := 0; i < b.N; i++ {
		Decode(jsonFile)
	}
}
