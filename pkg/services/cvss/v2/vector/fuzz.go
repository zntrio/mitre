// +build gofuzz

package vector

// Fuzz will be used for fuzzing testing purpose
func Fuzz(data []byte) int {
	v, err := FromString(string(data))
	if err != nil {
		if v != nil {
			panic("v != nil on error")
		}
		return 0
	}
	return 1
}
