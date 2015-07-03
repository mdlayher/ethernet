package ethernet

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func TestVLANMarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		v    *VLAN
		b    []byte
		err  error
	}{
		{
			desc: "VLAN priority too large",
			v: &VLAN{
				Priority: 8,
			},
			err: ErrInvalidVLAN,
		},
		{
			desc: "VLAN ID too large",
			v: &VLAN{
				ID: 4095,
			},
			err: ErrInvalidVLAN,
		},
		{
			desc: "empty VLAN",
			v:    &VLAN{},
			b:    []byte{0x00, 0x00},
		},
		{
			desc: "VLAN: PRI 1, ID 101",
			v: &VLAN{
				Priority: 1,
				ID:       101,
			},
			b: []byte{0x20, 0x65},
		},
		{
			desc: "VLANs: PRI 0, DROP, ID 100",
			v: &VLAN{
				DropEligible: true,
				ID:           100,
			},
			b: []byte{0x10, 0x64},
		},
	}

	for i, tt := range tests {
		b, err := tt.v.MarshalBinary()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected VLAN bytes:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}

func TestVLANUnmarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		b    []byte
		v    *VLAN
		err  error
	}{
		{
			desc: "nil buffer",
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "short buffer",
			b:    []byte{0},
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "VLAN ID too large",
			b:    []byte{0xff, 0xff},
			err:  ErrInvalidVLAN,
		},
		{
			desc: "VLAN: PRI 1, ID 101",
			b:    []byte{0x20, 0x65},
			v: &VLAN{
				Priority: 1,
				ID:       101,
			},
		},
		{
			desc: "VLAN: PRI 0, DROP, ID 100",
			b:    []byte{0x10, 0x64},
			v: &VLAN{
				DropEligible: true,
				ID:           100,
			},
		},
	}

	for i, tt := range tests {
		v := new(VLAN)
		if err := v.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.v, v; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected VLAN:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}
