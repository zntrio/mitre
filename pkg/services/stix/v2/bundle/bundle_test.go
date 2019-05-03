package bundle

import (
	"compress/gzip"
	"os"
	"testing"
)

func TestBundleLoader(t *testing.T) {

	jsonFile, err := os.Open("./internal/test/fixtures/identifying-a-threat-actor-profile.json.gz")
	if err != nil {
		t.Errorf("unable to open fixture file: %v", err)
	}
	defer jsonFile.Close()

	// Load all content
	gzContent, _ := gzip.NewReader(jsonFile)

	_, stats, err := Decode(gzContent)
	if err != nil {
		t.Errorf("unable to deocde bundle: %v", err)
	}

	if stats.Count != 3 {
		t.Error("invalid object count")
	}
}
