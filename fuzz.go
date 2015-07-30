// +build gofuzz

package ethernet

func Fuzz(data []byte) int {
	f := new(Frame)
	if err := f.UnmarshalBinary(data); err != nil {
		return 0
	}

	if _, err := f.MarshalBinary(); err != nil {
		panic(err)
	}

	return 1
}
