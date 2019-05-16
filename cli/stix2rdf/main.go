package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"go.zenithar.org/mitre/pkg/services/stix/v2/bundle"
)

func init() {
	flag.Parse()
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	var (
		data []byte
		err  error
	)

	switch flag.NArg() {
	case 0:
		data, err = ioutil.ReadAll(os.Stdin)
		check(err)
		break
	case 1:
		data, err = ioutil.ReadFile(flag.Arg(0))
		check(err)
		break
	default:
		fmt.Printf("input must be from stdin or file\n")
		os.Exit(1)
	}

	// Decode the bundle
	b, _, err := bundle.Decode(bytes.NewBuffer(data))
	check(err)

	// Iterate on each objects
	for _, sob := range b.Objects {
		// Convert as map via json
		jsonObject, err := json.Marshal(sob)
		check(err)

		var result map[string]interface{}
		check(json.Unmarshal(jsonObject, &result))

		// Extract id
		objectID, ok := result["id"]
		if !ok {
			panic("Object should have an id")
		}

		for k, v := range result {
			switch value := v.(type) {
			case []interface{}:
				for _, v := range value {
					if reflect.TypeOf(v).Kind() == reflect.Map {
						jsonValue, err := json.Marshal(v)
						check(err)
						fmt.Printf("_:%s <http://stix.mitre.org/2.0/%s> \"%s\" .\n", objectID, k, strings.Replace(string(jsonValue), "\"", "\\\"", -1))
					} else {
						fmt.Printf("_:%s <http://stix.mitre.org/2.0/%s> \"%s\" .\n", objectID, k, v)
					}
				}
			default:
				fmt.Printf("_:%s <http://stix.mitre.org/2.0/%s> \"%s\" .\n", objectID, k, v)
			}

		}
	}
}
