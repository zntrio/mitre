package vector

import (
	"testing"
)

func FuzzFromString(f *testing.F) {
	// Register corpus
	f.Add("AV:ND/AC:ND/Au:ND/C:ND/I:ND/A:ND/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND")
	f.Add("AV:N/AC:H/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H")
	f.Add("AV:N/AC:H/Au:N/C:C/I:C/A:C")
	f.Add("AV:N/AC:H/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:H/AR:H")
	f.Add("//////")
	f.Add("A:ND/////")
	f.Add("Au:ND/////")
	f.Add("AC:ND/////")
	f.Add("AV:N/AC:H/Au:N")
	f.Add("AV:N/AX:H/Au:N/C:C/I:C/A:C")
	f.Add("AV:N/AC:H/Au:N/C:C/I:C/A:C/X:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H")
	f.Add("AV:N/AC:H/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CRX:H/IR:H/AR:H")
	f.Add("AV:N/AC:X/Au:N/C:C/I:C/A:C")
	f.Add("AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H")
	f.Add("AV:A/AC:H/Au:N/C:C/I:C/A:C/Au:N")
	f.Add("AV:N/AC:H/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H")

	f.Fuzz(func(t *testing.T, vs string) {
		v, err := FromString(vs)
		if err != nil && v != nil {
			t.Fatalf("%q, %v", vs, err)
		}
		if err != nil {
			return
		}

		// Try to parse generated vector object
		out, err := ToString(v)
		if err != nil {
			t.Fatalf("%q is not parsable, got error: %v", vs, err)
		}
		if vs != out {
			t.Fatalf("input %q is different from output %q", vs, out)
		}
	})
}
