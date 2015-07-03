package ethernet

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"
)

func TestFrameMarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		f    *Frame
		b    []byte
		err  error
	}{
		{
			desc: "IPv4, no VLANs",
			f: &Frame{
				DestinationMAC: net.HardwareAddr{0, 1, 0, 1, 0, 1},
				SourceMAC:      net.HardwareAddr{1, 0, 1, 0, 1, 0},
				EtherType:      EtherTypeIPv4,
				Payload:        bytes.Repeat([]byte{0}, 50),
			},
			b: append([]byte{
				0, 1, 0, 1, 0, 1,
				1, 0, 1, 0, 1, 0,
				0x08, 0x00,
			}, bytes.Repeat([]byte{0}, 50)...),
		},
		{
			desc: "IPv6, 1 VLAN: PRI 1, ID 101",
			f: &Frame{
				DestinationMAC: net.HardwareAddr{1, 0, 1, 0, 1, 0},
				SourceMAC:      net.HardwareAddr{0, 1, 0, 1, 0, 1},
				VLAN: []*VLAN{{
					Priority: 1,
					ID:       101,
				}},
				EtherType: EtherTypeIPv6,
				Payload:   bytes.Repeat([]byte{0}, 50),
			},
			b: append([]byte{
				1, 0, 1, 0, 1, 0,
				0, 1, 0, 1, 0, 1,
				0x81, 0x00,
				0x20, 0x65,
				0x86, 0xDD,
			}, bytes.Repeat([]byte{0}, 50)...),
		},
		{
			desc: "ARP, 2 VLANs: (PRI 0, DROP, ID 100) (PRI 1, ID 101)",
			f: &Frame{
				DestinationMAC: Broadcast,
				SourceMAC:      net.HardwareAddr{0, 1, 0, 1, 0, 1},
				VLAN: []*VLAN{
					{
						DropEligible: true,
						ID:           100,
					},
					{
						Priority: 1,
						ID:       101,
					},
				},
				EtherType: EtherTypeARP,
				Payload:   bytes.Repeat([]byte{0}, 50),
			},
			b: append([]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0, 1, 0, 1, 0, 1,
				0x81, 0x00,
				0x10, 0x64,
				0x81, 0x00,
				0x20, 0x65,
				0x08, 0x06,
			}, bytes.Repeat([]byte{0}, 50)...),
		},
	}

	for i, tt := range tests {
		b, err := tt.f.MarshalBinary()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Frame bytes:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}

func TestFrameUnmarshalBinary(t *testing.T) {
	var tests = []struct {
		desc string
		b    []byte
		f    *Frame
		err  error
	}{
		{
			desc: "nil buffer",
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "short buffer",
			b:    bytes.Repeat([]byte{0}, 13),
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "short payload, no VLANs",
			b:    bytes.Repeat([]byte{0}, 45),
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "1 short VLAN",
			b: []byte{
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x81, 0x00,
				0x00,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "short payload, 1 VLAN",
			b: append([]byte{
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x81, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			}, bytes.Repeat([]byte{0}, 41)...),
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "short payload, 2 VLANs",
			b: append([]byte{
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x81, 0x00,
				0x00, 0x00,
				0x81, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			}, bytes.Repeat([]byte{0}, 37)...),
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "IPv4, no VLANs",
			b: append([]byte{
				0, 1, 0, 1, 0, 1,
				1, 0, 1, 0, 1, 0,
				0x08, 0x00,
			}, bytes.Repeat([]byte{0}, 50)...),
			f: &Frame{
				DestinationMAC: net.HardwareAddr{0, 1, 0, 1, 0, 1},
				SourceMAC:      net.HardwareAddr{1, 0, 1, 0, 1, 0},
				EtherType:      EtherTypeIPv4,
				Payload:        bytes.Repeat([]byte{0}, 50),
			},
		},
		{
			desc: "IPv6, 1 VLAN: PRI 1, ID 101",
			b: append([]byte{
				1, 0, 1, 0, 1, 0,
				0, 1, 0, 1, 0, 1,
				0x81, 0x00,
				0x20, 0x65,
				0x86, 0xDD,
			}, bytes.Repeat([]byte{0}, 50)...),
			f: &Frame{
				DestinationMAC: net.HardwareAddr{1, 0, 1, 0, 1, 0},
				SourceMAC:      net.HardwareAddr{0, 1, 0, 1, 0, 1},
				VLAN: []*VLAN{{
					Priority: 1,
					ID:       101,
				}},
				EtherType: EtherTypeIPv6,
				Payload:   bytes.Repeat([]byte{0}, 50),
			},
		},
		{
			desc: "ARP, 2 VLANs: (PRI 0, DROP, ID 100), (PRI 1, ID 101)",
			b: append([]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0, 1, 0, 1, 0, 1,
				0x81, 0x00,
				0x10, 0x64,
				0x81, 0x00,
				0x20, 0x65,
				0x08, 0x06,
			}, bytes.Repeat([]byte{0}, 50)...),
			f: &Frame{
				DestinationMAC: Broadcast,
				SourceMAC:      net.HardwareAddr{0, 1, 0, 1, 0, 1},
				VLAN: []*VLAN{
					{
						DropEligible: true,
						ID:           100,
					},
					{
						Priority: 1,
						ID:       101,
					},
				},
				EtherType: EtherTypeARP,
				Payload:   bytes.Repeat([]byte{0}, 50),
			},
		},
	}

	for i, tt := range tests {
		f := new(Frame)
		if err := f.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.f, f; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Frame:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}
